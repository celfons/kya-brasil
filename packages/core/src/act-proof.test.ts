import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { actText, checkActProof, spentToday, validateAct } from "./acts";
import { requestText } from "./request";
import type { AgentKey } from "./types";

const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const agent: AgentKey = { kind: "evm", id: account.address };
const CRED = "6d0b1c2e-1111-4222-8333-444455556666";
const ISSUER = "https://kya.test";
const now = new Date("2026-10-13T12:00:00Z");
const t = Math.floor(now.getTime() / 1000);
const BODY_HASH = "ab".repeat(32);

/** What the agent sends with "Sign in with KYA": the request text signed with its key. */
async function signedRequest(over: Partial<{ url: string; created: number; expires: number; content_sha256: string }> = {}) {
  const r = { method: "POST", url: "https://beta.com.br/orders", created: t - 30, expires: t + 30, content_sha256: BODY_HASH, ...over };
  const signature = await account.signMessage({ message: requestText({ credentialId: CRED, method: r.method, url: r.url, created: r.created, expires: r.expires, contentSha256: r.content_sha256 }) });
  return { ...r, signature };
}

describe("request text", () => {
  it("matches the npm client's requestText byte for byte (shared vector)", () => {
    expect(requestText({ credentialId: CRED, method: "post", url: "https://Beta.COM.br/orders?x=1#frag", created: 1, expires: 61, contentSha256: BODY_HASH })).toBe(
      ["KYA Brasil: request", `credential: ${CRED}`, "method: POST", "url: https://beta.com.br/orders?x=1", "created: 1", "expires: 61", `content-sha256: ${BODY_HASH}`].join("\n")
    );
  });
});

describe("act proof of origin (D-18)", () => {
  it("accepts the agent's signed request as proof", async () => {
    const act = validateAct({ action: "order", amount: 4200, currency: "BRL", agent_request: await signedRequest() });
    const p = await checkActProof({ issuer: ISSUER, credential_id: CRED, agent, act, now });
    expect(p.proof).toBe("agent_request");
    expect(p.proof_signature).toBe(act.agent_request?.signature);
  });

  it("accepts the agent's signature over the act text", async () => {
    const act = validateAct({ action: "pay", amount: 10, currency: "BRL" });
    act.agent_signature = await account.signMessage({ message: actText({ issuer: ISSUER, credential_id: CRED, agent, act }) });
    expect(await checkActProof({ issuer: ISSUER, credential_id: CRED, agent, act, now })).toMatchObject({ proof: "agent_signature", agent_signed: true });
  });

  it("an act without proof is 'none', not an error", async () => {
    expect(await checkActProof({ issuer: ISSUER, credential_id: CRED, agent, act: validateAct({ action: "pay" }), now })).toEqual({ proof: "none", agent_signed: false, proof_signature: null });
  });

  it("refuses a forged, altered, stale or mismatched request", async () => {
    const good = await signedRequest();
    const check = (r: Record<string, unknown>, extra: Record<string, unknown> = {}) => checkActProof({ issuer: ISSUER, credential_id: CRED, agent, act: validateAct({ action: "order", agent_request: r, ...extra }), now });
    await expect(check({ ...good, url: "https://evil.com/orders" })).rejects.toMatchObject({ code: "CHALLENGE_FAILED" });
    await expect(checkActProof({ issuer: ISSUER, credential_id: "other-credential", agent, act: validateAct({ action: "order", agent_request: good }), now })).rejects.toMatchObject({ code: "CHALLENGE_FAILED" });
    await expect(check(await signedRequest({ created: t - 90_000, expires: t - 89_970 }))).rejects.toThrow(/24 hours/);
    await expect(check(await signedRequest({ created: t + 3600, expires: t + 3660 }))).rejects.toThrow(/future/);
    await expect(check(await signedRequest({ expires: t + 3600 }))).rejects.toThrow(/lifetime/);
    await expect(check(good, { content_sha256: "cd".repeat(32) })).rejects.toThrow(/differs/);
  });

  it("validates the agent_request shape", () => {
    expect(() => validateAct({ action: "order", agent_request: "x" })).toThrow(/agent_request/);
    expect(() => validateAct({ action: "order", agent_request: { method: "POST", url: "ftp://x", created: 1, expires: 2, signature: "s" } })).toThrow(/url/);
    expect(() => validateAct({ action: "order", agent_request: { method: "POST", url: "https://x", created: "1", expires: 2, signature: "s" } })).toThrow(/created/);
  });

  it("the daily total adds only acts that count", () => {
    const acts = [
      { amount: 100, currency: "BRL", allowed: true, counted: true },
      { amount: 5000, currency: "BRL", allowed: true, counted: false },
      { amount: 7, currency: "BRL", allowed: false, counted: true }
    ];
    expect(spentToday(acts, "BRL")).toBe(100);
  });
});
