import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { KYA_HEADERS, checkMandate, createKyaAgent, createKyaAuth, requestText, signRequest, signResponse, verifyResponse } from "./auth";

const EVM_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const EVM = privateKeyToAccount(EVM_PK).address;
const CRED = "6d0b1c2e-1111-4222-8333-444455556666";
const mandate = { actions: ["order", "pay"], max_per_operation: { amount: 5000, currency: "BRL" }, max_per_day: { amount: 20000, currency: "BRL" }, currencies: ["BRL"], counterparties: ["12345678000190", "*.beta.com.br"], notes: "x" };

function issuer(overrides: Partial<{ status: string; agent: unknown }> = {}) {
  const calls: string[] = [];
  const fetchImpl = (async (url: string) => {
    calls.push(url);
    if (url.includes("/v1/agents/nope")) return new Response(JSON.stringify({ error: "NOT_FOUND", message: "unknown" }), { status: 404 });
    if (url.includes("/allowed")) return new Response(JSON.stringify({ allowed: true, reason: "inside the mandate" }));
    return new Response(JSON.stringify({ credential_id: CRED, status: overrides.status ?? "active", status_reason: null, agent: overrides.agent ?? { kind: "evm", id: EVM }, principal: { cnpj: "11222333000181", cnpj_formatted: "11.222.333/0001-81", legal_name: "ACME LTDA" }, credential: { mandate }, events: [] }));
  }) as unknown as typeof fetch;
  return { calls, auth: createKyaAuth({ baseUrl: "https://kya.test", fetch: fetchImpl }) };
}

describe("sign in with KYA", () => {
  it("authenticates a signed POST with body, exposes the context and caches the credential", async () => {
    const { auth, calls } = issuer();
    const body = JSON.stringify({ sku: "A1", qty: 3 });
    const url = "https://Beta.com.br/orders?x=1";
    const headers = await signRequest({ credentialId: CRED, key: { kind: "evm", privateKey: EVM_PK }, method: "POST", url, body });
    const req = new Request(url, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });
    const r = await auth.authenticate(req);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.kya.principal.legal_name).toBe("ACME LTDA");
    expect(r.kya.signer).toBe(EVM);
    expect(r.kya.body).toBe("verified");
    expect(r.kya.check({ action: "order", amount: 4200, currency: "BRL", counterparty: "beta.com.br" }).allowed).toBe(true);
    expect(r.kya.check({ action: "sign" }).allowed).toBe(false);
    expect((await r.kya.allowed({ action: "pay" })).allowed).toBe(true);
    await auth.authenticate(new Request(url, { method: "POST", headers: { ...headers }, body }));
    expect(calls.filter((c) => c.endsWith(`/v1/agents/${CRED}`)).length).toBe(1); // cached
  });

  it("rejects missing headers, expired, tampered body, bad signature, unknown and inactive credentials", async () => {
    const { auth } = issuer();
    const url = "https://beta.com.br/orders";
    expect((await auth.authenticate(new Request(url))).ok).toBe(false);
    const old = await signRequest({ credentialId: CRED, key: { kind: "evm", privateKey: EVM_PK }, method: "GET", url, now: new Date(Date.now() - 3600_000) });
    expect(await auth.authenticate(new Request(url, { headers: old }))).toMatchObject({ ok: false, status: 401, error: "KYA_SIGNATURE_EXPIRED" });
    const h = await signRequest({ credentialId: CRED, key: { kind: "evm", privateKey: EVM_PK }, method: "POST", url, body: "a" });
    expect(await auth.authenticate(new Request(url, { method: "POST", headers: h, body: "b" }))).toMatchObject({ ok: false, error: "KYA_BODY_MISMATCH" });
    const other = await signRequest({ credentialId: CRED, key: { kind: "evm", privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" }, method: "GET", url });
    expect(await auth.authenticate(new Request(url, { headers: other }))).toMatchObject({ ok: false, error: "KYA_BAD_SIGNATURE" });
    const unknown = await signRequest({ credentialId: "nope", key: { kind: "evm", privateKey: EVM_PK }, method: "GET", url });
    expect(await auth.authenticate(new Request(url, { headers: unknown }))).toMatchObject({ ok: false, status: 401, error: "KYA_CREDENTIAL_UNKNOWN" });
    const revoked = issuer({ status: "revoked" }).auth;
    const ok = await signRequest({ credentialId: CRED, key: { kind: "evm", privateKey: EVM_PK }, method: "GET", url });
    expect(await revoked.authenticate(new Request(url, { headers: ok }))).toMatchObject({ ok: false, status: 403, error: "KYA_CREDENTIAL_NOT_ACTIVE" });
  });

  it("supports Ed25519 (web-bot-auth) and ERC-8004 wallets", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const id = btoa(String.fromCharCode(...raw)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const url = "https://beta.com.br/quote";
    const ed = issuer({ agent: { kind: "web-bot-auth", id } }).auth;
    const h = await signRequest({ credentialId: CRED, key: { kind: "web-bot-auth", privateKey: kp.privateKey }, method: "GET", url });
    expect((await ed.authenticate(new Request(url, { headers: h }))).ok).toBe(true);
    const erc = issuer({ agent: { kind: "erc8004", id: "eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:7", wallet: EVM } }).auth;
    const h2 = await signRequest({ credentialId: CRED, key: { kind: "erc8004", privateKey: EVM_PK }, method: "GET", url });
    expect((await erc.authenticate(new Request(url, { headers: h2 }))).ok).toBe(true);
  });

  it("works as Hono middleware, Express middleware and fetch handler", async () => {
    const { auth } = issuer();
    const url = "https://beta.com.br/orders";
    const headers = await signRequest({ credentialId: CRED, key: { kind: "evm", privateKey: EVM_PK }, method: "GET", url });
    // hono-like
    const vars: Record<string, unknown> = {};
    const c = { req: { raw: new Request(url, { headers }) }, set: (k: string, v: unknown) => { vars[k] = v; }, json: (b: unknown, s?: number) => new Response(JSON.stringify(b), { status: s }) };
    let nexted = false;
    expect(await auth.hono()(c, async () => { nexted = true; })).toBeUndefined();
    expect(nexted && (vars.kya as { principal: { cnpj: string } }).principal.cnpj === "11222333000181").toBe(true);
    const denied = await auth.hono()({ ...c, req: { raw: new Request(url) } }, async () => {});
    expect(denied?.status).toBe(401);
    // express-like
    const req = { method: "GET", protocol: "https", originalUrl: "/orders", headers: { host: "beta.com.br", ...headers }, get: (n: string) => (n === "host" ? "beta.com.br" : undefined) } as Parameters<ReturnType<typeof auth.express>>[0];
    await new Promise<void>((resolve, reject) => auth.express()(req, { status: () => ({ status: () => ({}) as never, json: (b) => reject(new Error(JSON.stringify(b))) }), json: () => ({}) }, (err) => (err ? reject(err) : resolve())));
    expect(req.kya?.principal.legal_name).toBe("ACME LTDA");
    // fetch handler
    const handler = auth.fetchHandler(async (_r, kya) => new Response(kya.principal.cnpj));
    expect(await (await handler(new Request(url, { headers }))).text()).toBe("11222333000181");
    expect((await handler(new Request(url))).status).toBe(401);
  });

  it("request text and local mandate checks are stable", () => {
    expect(requestText({ credentialId: "c", method: "post", url: "https://Beta.com.br:443/a?b=1#frag", created: 1, expires: 2 }).split("\n")[3]).toBe("url: https://beta.com.br/a?b=1");
    const v = checkMandate(mandate, { action: "pay", amount: 6000, currency: "BRL", counterparty: "shop.beta.com.br" });
    expect(v.allowed).toBe(false);
    expect(v.checks.find((c) => c.rule === "max_per_operation")?.ok).toBe(false);
    expect(v.checks.find((c) => c.rule === "counterparties")?.ok).toBe(true);
    expect(v.not_evaluated).toEqual(["notes", "max_per_day (only the issuer knows today's registered total)"]);
  });
});

describe("mutual authentication", () => {
  it("caller and callee verify each other; a replayed response does not pass as a request", async () => {
    const BOB_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const BOB = privateKeyToAccount(BOB_PK).address;
    const BOB_CRED = "7e1c2d3f-2222-4333-8444-555566667777";
    const creds: Record<string, { status: string; agent: unknown }> = { [CRED]: { status: "active", agent: { kind: "evm", id: EVM } }, [BOB_CRED]: { status: "active", agent: { kind: "evm", id: BOB } } };
    const issuerFetch = (async (url: string) => {
      const id = url.split("/v1/agents/")[1]?.split(/[/?]/)[0] ?? "";
      const c = creds[id];
      if (!c) return new Response(JSON.stringify({ error: "NOT_FOUND", message: "unknown" }), { status: 404 });
      return new Response(JSON.stringify({ credential_id: id, status: c.status, status_reason: null, agent: c.agent, principal: { cnpj: "11222333000181", cnpj_formatted: "11.222.333/0001-81", legal_name: id === CRED ? "ALFA LTDA" : "BETA SA" }, credential: { mandate: { actions: ["order"] } }, events: [] }));
    }) as unknown as typeof fetch;

    // Beta (callee): a server that authenticates Alfa and signs its answer.
    const betaAuth = createKyaAuth({ baseUrl: "https://kya.test", fetch: issuerFetch });
    const betaServer = async (request: Request): Promise<Response> => {
      const r = await betaAuth.authenticate(request);
      if (!r.ok) return new Response(JSON.stringify({ error: r.error }), { status: r.status });
      const body = JSON.stringify({ accepted: true, seller: r.kya.principal.legal_name });
      const headers = await signResponse({ credentialId: BOB_CRED, key: { kind: "evm", privateKey: BOB_PK }, requestSignature: request.headers.get(KYA_HEADERS.signature)!, body });
      return new Response(body, { headers: { ...headers, "content-type": "application/json" } });
    };

    // Alfa (caller): signs the request, verifies who answered.
    const alfa = createKyaAgent({ credentialId: CRED, key: { kind: "evm", privateKey: EVM_PK }, authOptions: { baseUrl: "https://kya.test", fetch: issuerFetch }, fetch: (async (url: string, init?: RequestInit) => betaServer(new Request(url, init))) as unknown as typeof fetch });
    const { response, callee } = await alfa.fetch("https://beta.com.br/orders", { method: "POST", body: JSON.stringify({ sku: "A1" }), headers: { "content-type": "application/json" } });
    expect(response.status).toBe(200);
    expect(callee?.ok).toBe(true);
    if (callee?.ok) {
      expect(callee.kya.principal.legal_name).toBe("BETA SA");
      expect(callee.kya.body).toBe("verified");
    }

    // A response signed by Beta cannot be replayed as a request from Beta.
    const replay = new Request("https://alfa.com.br/x", { headers: { [KYA_HEADERS.credential]: BOB_CRED, [KYA_HEADERS.created]: response.headers.get(KYA_HEADERS.created)!, [KYA_HEADERS.expires]: response.headers.get(KYA_HEADERS.expires)!, [KYA_HEADERS.signature]: response.headers.get(KYA_HEADERS.signature)! } });
    expect(await betaAuth.authenticate(replay)).toMatchObject({ ok: false, error: "KYA_BAD_SIGNATURE" });

    // A signed response for another request is rejected.
    const other = await verifyResponse(betaAuth, response, "0xdeadbeef");
    expect(other).toMatchObject({ ok: false, error: "KYA_RESPONSE_MISMATCH" });
  });
});

describe("request text shared with the issuer (D-18)", () => {
  it("is byte-identical to the vector in packages/core/src/act-proof.test.ts", () => {
    const h = "ab".repeat(32);
    expect(requestText({ credentialId: CRED, method: "post", url: "https://Beta.COM.br/orders?x=1#frag", created: 1, expires: 61, contentSha256: h })).toBe(
      ["KYA Brasil: request", `credential: ${CRED}`, "method: POST", "url: https://beta.com.br/orders?x=1", "created: 1", "expires: 61", `content-sha256: ${h}`].join("\n")
    );
  });
});

describe("the verified request becomes the act's proof of origin (D-18)", () => {
  it("exposes kya.request with the signed headers, ready for kya.registerAct", async () => {
    const { auth } = issuer();
    const body = JSON.stringify({ sku: "A1", qty: 3 });
    const url = "https://beta.com.br/orders";
    const headers = await signRequest({ credentialId: CRED, key: { kind: "evm", privateKey: EVM_PK }, method: "POST", url, body });
    const r = await auth.authenticate(new Request(url, { method: "POST", headers, body }));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.kya.request).toEqual({
      method: "POST",
      url,
      created: Number(headers[KYA_HEADERS.created]),
      expires: Number(headers[KYA_HEADERS.expires]),
      content_sha256: headers[KYA_HEADERS.content],
      signature: headers[KYA_HEADERS.signature]
    });
    expect(typeof r.kya.registerAct).toBe("function");
  });
});
