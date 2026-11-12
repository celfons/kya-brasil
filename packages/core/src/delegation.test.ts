import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { base64url } from "./challenge.js";
import { type Delegation, type DelegationAnchor, DELEGATED_MANDATE_MAX_BYTES, checkDelegatedAction, decodeDelegationHeader, delegationRef, encodeDelegationHeader, mandateSubsetProblems, prepareDelegation, verifyDelegationChain } from "./delegation.js";
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

// Mutation testing (research/mutation) showed that these edges could be moved without any test failing.
describe("delegation at the edge of each rule", () => {
  const HASH = "ab".repeat(32);
  const verify = (chain: unknown, now = NOW, anchor: DelegationAnchor = credential) => verifyDelegationChain({ credential: anchor, chain, now });
  const first = (mandate: unknown = childMandate, ttlSeconds = 600) => link({ signer: evmSigner(ROOT), delegate: { kind: "evm", id: CHILD.address }, mandate, ttlSeconds });

  it("contains a ceiling, a window and a lifetime that are equal to the parent's, and nothing above them", () => {
    const parent = validateMandate({ max_per_operation: { amount: 5000, currency: "BRL" }, max_per_day: { amount: 20000, currency: "BRL" }, valid_from: "2026-11-01T00:00:00Z", valid_until: "2026-12-01T00:00:00Z", delegation: { max_depth: 2, max_ttl_seconds: 3600 } });
    const same = { max_per_operation: { amount: 5000, currency: "BRL" }, max_per_day: { amount: 20000, currency: "BRL" }, valid_from: "2026-11-01T00:00:00Z", valid_until: "2026-12-01T00:00:00Z" };
    const child = (over: object) => validateMandate({ ...same, ...over });
    expect(mandateSubsetProblems(parent, child({ delegation: { max_depth: 1, max_ttl_seconds: 3600 } }))).toEqual([]);
    expect(mandateSubsetProblems(parent, child({}))).toEqual([]);
    expect(mandateSubsetProblems(parent, child({ max_per_operation: { amount: 5000.01, currency: "BRL" } }))).toEqual(["max_per_operation: 5000.01 is above the parent's 5000"]);
    expect(mandateSubsetProblems(parent, child({ max_per_day: { amount: 20000.01, currency: "BRL" } }))).toEqual(["max_per_day: 20000.01 is above the parent's 20000"]);
    expect(mandateSubsetProblems(parent, child({ max_per_day: { amount: 1, currency: "USD" } }))).toEqual(["max_per_day: currency USD differs from the parent's BRL"]);
    expect(mandateSubsetProblems(parent, child({ max_per_day: undefined }))).toEqual(["max_per_day: parent sets a ceiling, delegated mandate must too"]);
    expect(mandateSubsetProblems(parent, child({ valid_from: "2026-10-31T23:59:59Z" }))).toEqual(["valid_from: delegated mandate starts before the parent's"]);
    expect(mandateSubsetProblems(parent, child({ valid_from: undefined }))).toEqual(["valid_from: delegated mandate starts before the parent's"]);
    expect(mandateSubsetProblems(parent, child({ valid_until: "2026-12-01T00:00:01Z" }))).toEqual(["valid_until: delegated mandate ends after the parent's"]);
    expect(mandateSubsetProblems(parent, child({ valid_until: undefined }))).toEqual(["valid_until: delegated mandate ends after the parent's"]);
    // One level below a parent of depth 2 may delegate one level more, not two.
    expect(mandateSubsetProblems(parent, child({ delegation: { max_depth: 2, max_ttl_seconds: 3600 } }))).toEqual(["delegation.max_depth: at most 1 below this level"]);
    expect(mandateSubsetProblems(parent, child({ delegation: { max_depth: 1, max_ttl_seconds: 3601 } }))).toEqual(["delegation.max_ttl_seconds: above the parent's 3600"]);
    expect(mandateSubsetProblems(child({}), child({ delegation: { max_depth: 1, max_ttl_seconds: 60 } }))).toEqual(["delegation: parent does not allow further delegation"]);
    // A parent that may delegate one level leaves nothing to delegate below it.
    const last = validateMandate({ delegation: { max_depth: 1, max_ttl_seconds: 3600 } });
    expect(mandateSubsetProblems(last, validateMandate({ delegation: { max_depth: 1, max_ttl_seconds: 60 } }))).toEqual(["delegation.max_depth: at most 0 below this level"]);
  });

  it("contains payment instruments and counterparties only when the child lists some of the parent's", () => {
    const visa = { network: "visa", ref_sha256: HASH };
    const elo = { network: "elo", ref_sha256: "cd".repeat(32) };
    const parent = validateMandate({ payment_instruments: [visa, elo] });
    expect(mandateSubsetProblems(parent, validateMandate({ payment_instruments: [elo] }))).toEqual([]);
    expect(mandateSubsetProblems(parent, validateMandate({}))).toEqual(["payment_instruments: parent restricts instruments, delegated mandate must list them"]);
    expect(mandateSubsetProblems(parent, validateMandate({ payment_instruments: [] }))).toEqual(["payment_instruments: parent restricts instruments, delegated mandate must list them"]);
    // The network and the hash must both be the parent's: one of each from two instruments is not an instrument.
    expect(mandateSubsetProblems(parent, validateMandate({ payment_instruments: [{ network: "visa", ref_sha256: elo.ref_sha256 }] }))).toEqual([`payment_instruments: visa ${elo.ref_sha256.slice(0, 12)}… is not in the parent mandate`]);
    expect(mandateSubsetProblems(parent, validateMandate({ payment_instruments: [visa, { network: "pix", ref_sha256: HASH }] }))).toEqual([`payment_instruments: pix ${HASH.slice(0, 12)}… is not in the parent mandate`]);
    // An empty list in the parent restricts nothing.
    expect(mandateSubsetProblems(validateMandate({ payment_instruments: [], counterparties: [] }), validateMandate({ payment_instruments: [visa], counterparties: ["any.example.com"] }))).toEqual([]);
    expect(mandateSubsetProblems(validateMandate({ counterparties: ["a.example.com"] }), validateMandate({ counterparties: [] }))).toEqual(["counterparties: parent restricts counterparties, delegated mandate must list them"]);
  });

  it("prepares a delegation with a lifetime from 60 seconds to the policy's, and a mandate of up to 2048 bytes", async () => {
    const prepare = (ttlSeconds: number, mandate: unknown = childMandate, delegate: { kind: string; id: string } = { kind: "evm", id: CHILD.address }) => prepareDelegation({ credential, delegate, mandate, ttlSeconds, now: NOW });
    expect((await prepare(60)).delegation.expires_at).toBe("2026-10-14T12:01:00.000Z");
    expect((await prepare(3600)).delegation.expires_at).toBe("2026-10-14T13:00:00.000Z");
    for (const ttl of [59, 3601, 600.5, Number.NaN]) await expect(prepare(ttl)).rejects.toThrow("ttlSeconds must be from 60 to 3600");
    await expect(prepare(600, childMandate, { kind: "erc8004", id: "eip155:1:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:7" })).rejects.toThrow("delegate must be an evm or web-bot-auth key");
    const sized = (n: number) => {
      const base = { ...childMandate, note: "" };
      return { ...base, note: "x".repeat(n - JSON.stringify(validateMandate(base)).length) };
    };
    expect(DELEGATED_MANDATE_MAX_BYTES).toBe(2048);
    expect(JSON.stringify((await prepare(600, sized(2048))).delegation.mandate)).toHaveLength(2048);
    await expect(prepare(600, sized(2049))).rejects.toThrow("delegated mandate larger than 2048 bytes");
    // The first link names no parent, and the text says so.
    const { text, delegation } = await prepare(600);
    expect(delegation.parent).toBeNull();
    expect(text.split("\n")).toEqual(["KYA Brasil: delegation", `credential: ${credential.credential_id}`, "parent: -", `delegate: evm:${CHILD.address}`, "depth: 1", "issued: 2026-10-14T12:00:00.000Z", "expires: 2026-10-14T12:10:00.000Z", expect.stringMatching(/^mandate-sha256: [0-9a-f]{64}$/)]);
  });

  it("verifies a chain of three links, the deepest the format allows", async () => {
    const deep: DelegationAnchor = { ...credential, mandate: validateMandate({ actions: ["quote"], delegation: { max_depth: 3, max_ttl_seconds: 3600 } }) };
    const make = async (chain: Delegation[], signer: typeof ROOT, delegate: typeof ROOT, mandate: unknown) => {
      const { delegation, text } = await prepareDelegation({ credential: deep, chain, delegate: { kind: "evm", id: delegate.address }, mandate, ttlSeconds: 600, now: NOW });
      return { ...delegation, signature: await signer.signMessage({ message: text }) };
    };
    const d1 = await make([], ROOT, CHILD, { actions: ["quote"], delegation: { max_depth: 2, max_ttl_seconds: 600 } });
    const d2 = await make([d1], CHILD, ROOT, { actions: ["quote"], delegation: { max_depth: 1, max_ttl_seconds: 600 } });
    const d3 = await make([d1, d2], ROOT, CHILD, { actions: ["quote"] });
    expect(d2.parent).toBe(await delegationRef(d1));
    const r = await verify([d1, d2, d3], NOW, deep);
    expect(r).toMatchObject({ ok: true, depth: 3, ref: await delegationRef(d3) });
    // The same link twice is refused by its number, named in the message.
    expect(await verify([d1, d1], NOW, deep)).toEqual({ ok: false, error: "KYA_DELEGATION_MALFORMED", message: "delegation 2: depth must be 2" });
    expect(await verify([{ ...d1, depth: 2 }], NOW, deep)).toEqual({ ok: false, error: "KYA_DELEGATION_MALFORMED", message: "delegation 1: depth must be 1" });
    // A link below one whose mandate does not delegate.
    const d4 = { ...d3, depth: 4, parent: await delegationRef(d3) };
    expect(await verify([d1, d2, d3, d4], NOW, deep)).toMatchObject({ ok: false, error: "KYA_DELEGATION_TOO_DEEP" });
    const end = await make([], ROOT, CHILD, { actions: ["quote"] });
    const below = { ...d2, parent: await delegationRef(end) };
    expect(await verify([end, below], NOW, deep)).toEqual({ ok: false, error: "KYA_DELEGATION_NOT_ALLOWED", message: "delegation 2: the delegator's mandate does not allow further delegation" });
    expect(await verify([d1], NOW, { ...deep, mandate: validateMandate({ actions: ["quote"] }) })).toEqual({ ok: false, error: "KYA_DELEGATION_NOT_ALLOWED", message: "the credential's mandate does not allow delegation" });
  });

  it("refuses a link that is not a v1 delegation in normalized form", async () => {
    const d1 = await first();
    const malformed = { ok: false, error: "KYA_DELEGATION_MALFORMED", message: "delegation 1: not a v1 delegation" };
    for (const raw of [null, 5, "x", { ...d1, version: 2 }, { ...d1, signature: undefined }, { ...d1, signature: 5 }, { ...d1, issued_at: 1 }, { ...d1, expires_at: 1 }]) expect(await verify([raw])).toEqual(malformed);
    expect(await verify([d1], NOW, { ...credential, expires_at: "never" })).toEqual({ ok: false, error: "KYA_DELEGATION_MALFORMED", message: "the credential has no valid expires_at" });
    expect(await verify([{ ...d1, delegate: { kind: "erc8004", id: "eip155:1:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:7" } }])).toMatchObject({ ok: false, error: "KYA_DELEGATION_MALFORMED" });
    expect(await verify([{ ...d1, delegate: undefined }])).toMatchObject({ ok: false, error: "KYA_DELEGATION_MALFORMED" });
    expect(await verify([{ ...d1, delegate: { kind: "evm", id: CHILD.address.toLowerCase() } }])).toEqual({ ok: false, error: "KYA_DELEGATION_MALFORMED", message: "delegation 1: delegate or mandate not in normalized form" });
    expect(await verify([{ ...d1, mandate: { ...d1.mandate, counterparties: ["SHOP.beta.com.br"] } }])).toEqual({ ok: false, error: "KYA_DELEGATION_MALFORMED", message: "delegation 1: delegate or mandate not in normalized form" });
    for (const times of [{ issued_at: "x" }, { expires_at: "x" }, { expires_at: d1.issued_at }, { issued_at: d1.expires_at }]) expect(await verify([{ ...d1, ...times }])).toEqual({ ok: false, error: "KYA_DELEGATION_MALFORMED", message: "delegation 1: bad issued_at / expires_at" });
  });

  it("accepts a link at the limit of its lifetime, of the link above it, of the clock tolerance and of its expiry", async () => {
    // As long as the policy allows, to the second.
    const full = await first(childMandate, 3600);
    expect(await verify([full])).toMatchObject({ ok: true });
    expect(await verify([{ ...full, expires_at: "2026-10-14T13:00:00.001Z" }])).toEqual({ ok: false, error: "KYA_DELEGATION_TTL", message: "delegation 1: lives longer than 3600s" });
    // Ending with the credential, and not after it.
    const short: DelegationAnchor = { ...credential, expires_at: "2026-10-14T12:10:00.000Z" };
    const d1 = await first();
    expect(d1.expires_at).toBe(short.expires_at);
    expect(await verify([d1], NOW, short)).toMatchObject({ ok: true, expires_at: short.expires_at });
    expect(await verify([d1], NOW, { ...credential, expires_at: "2026-10-14T12:09:59.999Z" })).toEqual({ ok: false, error: "KYA_DELEGATION_TTL", message: "delegation 1: outlives the link above it" });
    // Issued up to five minutes ahead of the verifier's clock.
    expect(await verify([d1], new Date(NOW.getTime() - 300_000))).toMatchObject({ ok: true });
    expect(await verify([d1], new Date(NOW.getTime() - 300_001))).toEqual({ ok: false, error: "KYA_DELEGATION_NOT_YET_VALID", message: "delegation 1: issued in the future" });
    // Valid through the instant it expires.
    expect(await verify([d1], new Date("2026-10-14T12:10:00.000Z"))).toMatchObject({ ok: true });
    expect(await verify([d1], new Date("2026-10-14T12:10:00.001Z"))).toEqual({ ok: false, error: "KYA_DELEGATION_EXPIRED", message: "delegation 1: expired at 2026-10-14T12:10:00.000Z" });
  });

  it("allows no action on an empty list of mandates, and carries a chain in a header of any length", () => {
    expect(checkDelegatedAction([], { action: "quote" })).toEqual({ allowed: false, levels: [] });
    for (const note of ["", "a", "aa", "aaa", "???>>>", "é"]) {
      const chain = [{ mandate: { note } }] as unknown as Delegation[];
      const header = encodeDelegationHeader(chain);
      expect(header).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(decodeDelegationHeader(` ${header}\n`)).toEqual(chain);
    }
    expect(encodeDelegationHeader([{ mandate: { note: "???>>>" } }] as unknown as Delegation[])).toMatch(/[_-]/);
    for (const bad of ["%%%", "e30x", ""]) expect(() => decodeDelegationHeader(bad)).toThrow("KYA-Delegation is not base64url JSON");
  });
});
