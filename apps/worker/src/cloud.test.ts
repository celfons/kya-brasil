import { describe, expect, it } from "vitest";
import "@kya-brasil/core"; // loads reflect-metadata before @peculiar/x509
import * as x509 from "@peculiar/x509";
import type { CloudSignatureProvider } from "@kya-brasil/core";
import { buildHttpApp } from "./http/routes";
import type { AppEnv } from "./env";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const ID = "6d0b1c2e-1111-4222-8333-444455556666";
const CH = "9e10d457-b396-4d28-8167-134d02593610";
const TEXT = "KYA Brasil: prove this agent key acts for a company\nissuer: https://kya.test\ncnpj: 11222333000181";

/** KV and D1 fakes: one pending agent with one live challenge. */
function env() {
  const kv = new Map<string, string>();
  const rows: Record<string, unknown> = {
    agents: { id: ID, cnpj: "11222333000181", status: "pending", mandate: "{}", agent_kind: "evm", agent_id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" },
    challenges: { id: CH, agent_row: ID, text: TEXT, expires_at: new Date(Date.now() + 600_000).toISOString() }
  };
  const e = {
    X402_NETWORK: "eip155:84532",
    X402_FACILITATOR_URL: "https://x402.org/facilitator",
    FREE_TIER_DAILY_LIMIT: "50",
    PAY_TO: "0x0000000000000000000000000000000000000001",
    CACHE: {
      get: async (k: string) => kv.get(k) ?? null,
      put: async (k: string, v: string) => void kv.set(k, v),
      delete: async (k: string) => void kv.delete(k)
    },
    DB: {
      prepare: (sql: string) => ({
        bind() { return this; },
        first: async () => (/FROM agents WHERE id/.test(sql) ? rows.agents : /FROM challenges WHERE id/.test(sql) ? rows.challenges : null),
        all: async () => ({ results: [] }),
        run: async () => ({})
      })
    }
  };
  return { env: e as unknown as AppEnv, kv };
}

async function mockProvider() {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=ACME LTDA:11222333000181", notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, keys });
  const seen = { challenge: "", verifierOk: false, hashes: 0, closed: 0 };
  const provider: CloudSignatureProvider = {
    id: "mock-psc",
    name: "PSC de teste",
    authorizationUrl: ({ redirectUri, state, codeChallenge }) => {
      seen.challenge = codeChallenge;
      return `https://psc.example/authorize?redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&code_challenge=${codeChallenge}`;
    },
    async exchangeCode({ code, codeVerifier }) {
      const s256 = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier))))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      seen.verifierOk = code === "good-code" && s256 === seen.challenge;
      if (!seen.verifierOk) throw new Error("PKCE mismatch");
      return {
        certificates: async () => [new Uint8Array(cert.rawData)],
        signHash: async (hash) => { seen.hashes++; expect(hash.length).toBe(32); return new Uint8Array(256).fill(1); },
        close: async () => void seen.closed++
      };
    }
  };
  return { provider, seen };
}

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

describe("cloud e-CNPJ on /sign (D-28)", () => {
  it("no provider configured: no cloud option, start is 404", async () => {
    const { env: e } = env();
    const app = buildHttpApp(e);
    const page = await (await app.fetch(new Request("https://kya.test/sign"), e, ctx)).text();
    expect(page).not.toContain("Certificado em nuvem");
    const r = await app.fetch(new Request(`https://kya.test/sign/cloud/x/start?id=${ID}&challenge_id=${CH}&agent_signature=0xab`), e, ctx);
    expect(r.status).toBe(404);
  });

  it("start redirects with state + PKCE; the callback consumes the state once, signs the stored challenge and calls prove", async () => {
    const { env: e, kv } = env();
    const { provider, seen } = await mockProvider();
    const app = buildHttpApp(e, { cloudProviders: [provider] });
    const page = await (await app.fetch(new Request("https://kya.test/sign"), e, ctx)).text();
    expect(page).toContain("Assinar com PSC de teste");

    const missing = await app.fetch(new Request(`https://kya.test/sign/cloud/mock-psc/start?id=${ID}&challenge_id=${CH}`), e, ctx);
    expect(missing.status).toBe(400);

    const start = await app.fetch(new Request(`https://kya.test/sign/cloud/mock-psc/start?id=${ID}&challenge_id=${CH}&agent_signature=0xab`), e, ctx);
    expect(start.status).toBe(302);
    const to = new URL(start.headers.get("location")!);
    expect(to.origin).toBe("https://psc.example");
    expect(to.searchParams.get("redirect_uri")).toBe("https://kya.test/sign/cloud/callback");
    const state = to.searchParams.get("state")!;
    expect(kv.has(`cloud:state:${state}`)).toBe(true);
    expect(kv.get(`cloud:state:${state}`)).not.toContain(seen.challenge); // the verifier is stored, never the challenge alone

    const cb = await app.fetch(new Request(`https://kya.test/sign/cloud/callback?code=good-code&state=${state}`), e, ctx);
    const body = await cb.text();
    expect(seen.verifierOk).toBe(true);
    expect(seen.hashes).toBe(1);
    expect(seen.closed).toBe(1);
    expect(kv.has(`cloud:state:${state}`)).toBe(false);
    // prove ran with the CMS: it stops at the (fake) agent signature, which proves the flow reached issuance.
    expect(body).toContain("Credencial não emitida");
    expect(body).toMatch(/agent_signature|challenge/);
    expect(cb.headers.get("content-security-policy")).toContain("default-src 'none'");

    const replay = await (await app.fetch(new Request(`https://kya.test/sign/cloud/callback?code=good-code&state=${state}`), e, ctx)).text();
    expect(replay).toContain("already used");
  });

  it("a refusal at the provider ends the flow without signing", async () => {
    const { env: e } = env();
    const { provider, seen } = await mockProvider();
    const app = buildHttpApp(e, { cloudProviders: [provider] });
    const start = await app.fetch(new Request(`https://kya.test/sign/cloud/mock-psc/start?id=${ID}&challenge_id=${CH}&agent_signature=0xab`), e, ctx);
    const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
    const body = await (await app.fetch(new Request(`https://kya.test/sign/cloud/callback?error=access_denied&state=${state}`), e, ctx)).text();
    expect(body).toContain("did not authorize");
    expect(seen.hashes).toBe(0);
  });
});
