import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { base64url } from "./challenge.js";
import { type Delegation, type DelegationAnchor, checkDelegatedAction, decodeDelegationHeader, encodeDelegationHeader, mandateSubsetProblems, prepareDelegation, verifyDelegationChain } from "./delegation.js";
import { validateMandate } from "./mandate.js";

const ROOT = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const CHILD = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const NOW = new Date("2026-10-14T12:00:00Z");

const credential: DelegationAnchor = {
  credential_id: "6d0b1c2e-1111-4222-8333-444455556666",
  agent: { kind: "evm", id: ROOT.address },
  expires_at: "2026-12-31T00:00:00Z",
  mandate: validateMandate({
    actions: ["quote", "order", "pay"],
    max_per_operation: { amount: 5000, currency: "BRL" },
    currencies: ["BRL"],
    counterparties: ["12345678000190", "*.beta.com.br"],
    delegation: { max_depth: 2, max_ttl_seconds: 3600 }
  })
};

async function grandchild() {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const id = base64url.encode(new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer));
  return { id, privateKey: kp.privateKey };
}

async function link(p: { chain?: Delegation[]; signer: (text: string) => Promise<string>; delegate: { kind: string; id: string }; mandate: unknown; ttlSeconds?: number; now?: Date }): Promise<Delegation> {
  const { delegation, text } = await prepareDelegation({ credential, chain: p.chain, delegate: p.delegate, mandate: p.mandate, ttlSeconds: p.ttlSeconds ?? 600, now: p.now ?? NOW });
  return { ...delegation, signature: await p.signer(text) };
}

const evmSigner = (acct: typeof ROOT) => (text: string) => acct.signMessage({ message: text });
const childMandate = { actions: ["quote", "order"], max_per_operation: { amount: 500, currency: "BRL" }, currencies: ["BRL"], counterparties: ["shop.beta.com.br"], delegation: { max_depth: 1, max_ttl_seconds: 600 } };

describe("delegation (D-30)", () => {
  it("verifies a two-level chain offline and evaluates every mandate in it", async () => {
    const d1 = await link({ signer: evmSigner(ROOT), delegate: { kind: "evm", id: CHILD.address }, mandate: childMandate });
    const gc = await grandchild();
    const d2 = await link({ chain: [d1], signer: evmSigner(CHILD), delegate: { kind: "web-bot-auth", id: gc.id }, mandate: { actions: ["quote"], max_per_operation: { amount: 100, currency: "BRL" }, currencies: ["BRL"], counterparties: ["shop.beta.com.br"] } });
    const chain = decodeDelegationHeader(encodeDelegationHeader([d1, d2]));
    const r = await verifyDelegationChain({ credential, chain, now: NOW });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.delegate).toEqual({ kind: "web-bot-auth", id: gc.id });
    expect(r.depth).toBe(2);
    expect(r.mandates).toHaveLength(3);
    expect(checkDelegatedAction(r.mandates, { action: "quote", amount: 80, currency: "BRL", counterparty: "shop.beta.com.br", now: NOW }).allowed).toBe(true);
    // Allowed by the credential and by level 1, refused by level 2.
    const order = checkDelegatedAction(r.mandates, { action: "order", amount: 80, currency: "BRL", now: NOW });
    expect(order.allowed).toBe(false);
    expect(order.levels.map((l) => l.allowed)).toEqual([true, true, false]);
  });

  it("refuses to prepare a broader, deeper or longer delegation", async () => {
    const noDelegation = { ...credential, mandate: validateMandate({ actions: ["quote"] }) };
    await expect(prepareDelegation({ credential: noDelegation, delegate: { kind: "evm", id: CHILD.address }, mandate: { actions: ["quote"] }, ttlSeconds: 600 })).rejects.toThrow(/does not allow delegation/);
    await expect(prepareDelegation({ credential, delegate: { kind: "evm", id: CHILD.address }, mandate: { actions: ["sign"] }, ttlSeconds: 600 })).rejects.toThrow(/broader/);
    await expect(prepareDelegation({ credential, delegate: { kind: "evm", id: CHILD.address }, mandate: childMandate, ttlSeconds: 7200 })).rejects.toThrow(/ttlSeconds/);
    const d1 = await link({ signer: evmSigner(ROOT), delegate: { kind: "evm", id: CHILD.address }, mandate: { ...childMandate, delegation: undefined } });
    await expect(prepareDelegation({ credential, chain: [d1], delegate: { kind: "evm", id: ROOT.address }, mandate: { actions: ["quote"] }, ttlSeconds: 60 })).rejects.toThrow(/further delegation/);
  });

  it("lists why a mandate is not contained in another", () => {
    const parent = credential.mandate;
    expect(mandateSubsetProblems(parent, validateMandate(childMandate))).toEqual([]);
    const p = mandateSubsetProblems(parent, validateMandate({ actions: ["quote", "sign"], max_per_operation: { amount: 9000, currency: "BRL" }, currencies: ["USDC"], counterparties: ["other.com.br"], delegation: { max_depth: 2, max_ttl_seconds: 7200 } }));
    expect(p.join("\n")).toMatch(/"sign"/);
    expect(p.join("\n")).toMatch(/9000/);
    expect(p.join("\n")).toMatch(/USDC/);
    expect(p.join("\n")).toMatch(/other\.com\.br/);
    expect(p.join("\n")).toMatch(/max_depth/);
    expect(p.join("\n")).toMatch(/max_ttl_seconds/);
    // Leaving open what the parent restricts is broader.
    expect(mandateSubsetProblems(parent, validateMandate({}))).toHaveLength(4);
    // A wildcard child is covered by a wildcard parent on the same or a higher domain.
    expect(mandateSubsetProblems(parent, validateMandate({ actions: ["quote"], max_per_operation: { amount: 1, currency: "BRL" }, currencies: ["BRL"], counterparties: ["*.shop.beta.com.br", "beta.com.br"] }))).toEqual([]);
  });

  it("rejects forged, tampered, expired, re-parented and over-long chains", async () => {
    const d1 = await link({ signer: evmSigner(ROOT), delegate: { kind: "evm", id: CHILD.address }, mandate: childMandate });
    const verify = (chain: unknown, now = NOW) => verifyDelegationChain({ credential, chain, now });

    // Signed by the delegate itself instead of the credential's agent.
    const forged = await link({ signer: evmSigner(CHILD), delegate: { kind: "evm", id: CHILD.address }, mandate: childMandate });
    expect(await verify([forged])).toMatchObject({ ok: false, error: "KYA_DELEGATION_BAD_SIGNATURE" });
    // Mandate widened after signing (still a subset of the credential, but not what was signed).
    expect(await verify([{ ...d1, mandate: { ...d1.mandate, max_per_operation: { amount: 900, currency: "BRL" } } }])).toMatchObject({ ok: false, error: "KYA_DELEGATION_BAD_SIGNATURE" });
    // Widened beyond the credential.
    expect(await verify([{ ...d1, mandate: { ...d1.mandate, actions: ["quote", "sign"] } }])).toMatchObject({ ok: false, error: "KYA_DELEGATION_BROADER" });
    expect(await verify([d1], new Date(NOW.getTime() + 3_600_000))).toMatchObject({ ok: false, error: "KYA_DELEGATION_EXPIRED" });
    expect(await verify([{ ...d1, credential_id: "other" }])).toMatchObject({ ok: false, error: "KYA_DELEGATION_MISMATCH" });
    expect(await verify([{ ...d1, expires_at: "2026-10-14T20:00:00.000Z" }])).toMatchObject({ ok: false, error: "KYA_DELEGATION_TTL" });
    expect(await verify([])).toMatchObject({ ok: false, error: "KYA_DELEGATION_MALFORMED" });
    expect(await verify("x")).toMatchObject({ ok: false, error: "KYA_DELEGATION_MALFORMED" });

    // A second link whose parent is not the first one.
    const gc = await grandchild();
    const d2 = await link({ chain: [d1], signer: evmSigner(CHILD), delegate: { kind: "web-bot-auth", id: gc.id }, mandate: { actions: ["quote"], max_per_operation: { amount: 1, currency: "BRL" }, currencies: ["BRL"], counterparties: ["shop.beta.com.br"] } });
    expect(await verify([d1, { ...d2, parent: "00".repeat(32) }])).toMatchObject({ ok: false, error: "KYA_DELEGATION_MISMATCH" });
    // Depth beyond what the mandate allows (credential max_depth 2, level 1 max_depth 1).
    const d3 = { ...d2, depth: 3, parent: d2.signature };
    expect(await verify([d1, d2, d3])).toMatchObject({ ok: false });
    expect(await verify([d1, d2, d2, d2])).toMatchObject({ ok: false, error: "KYA_DELEGATION_TOO_DEEP" });
  });

  it("never outlives the credential", async () => {
    const short = { ...credential, expires_at: "2026-10-14T12:05:00Z" };
    const { delegation } = await prepareDelegation({ credential: short, delegate: { kind: "evm", id: CHILD.address }, mandate: childMandate, ttlSeconds: 3600, now: NOW });
    expect(delegation.expires_at).toBe("2026-10-14T12:05:00.000Z");
  });

  it("validates the delegation policy in the mandate", () => {
    expect(() => validateMandate({ delegation: { max_depth: 4, max_ttl_seconds: 600 } })).toThrow(/max_depth/);
    expect(() => validateMandate({ delegation: { max_depth: 1, max_ttl_seconds: 10 } })).toThrow(/max_ttl_seconds/);
    expect(() => validateMandate({ delegation: { max_depth: 1, max_ttl_seconds: 600, extra: 1 } })).toThrow(/unknown/);
    expect(validateMandate({ delegation: { max_depth: 1, max_ttl_seconds: 600 } }).delegation).toEqual({ max_depth: 1, max_ttl_seconds: 600 });
  });
});
