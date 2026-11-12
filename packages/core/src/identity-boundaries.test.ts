// Edges of the CPF check, of the canonical JSON strings and of the signed answers. Mutation testing
// (research/mutation) showed that they could be moved without any test failing.
import { describe, expect, it } from "vitest";
import { canonicalize, generateAttestationKey, importPrivateKey, publicJwkFromPrivate, signAttestation, verifyAttestation } from "./attestation.js";
import { isValidCpf } from "./person.js";

describe("CPF check digits", () => {
  it("accepts a remainder of 10 as the digit 0, in either position", () => {
    for (const v of ["10000000108", "10000002810", "529.982.247-25"]) expect(isValidCpf(v), v).toBe(true);
  });
  it("refuses one wrong digit in either position, a wrong length and a repeated digit", () => {
    for (const v of ["52998224735", "52998224724", "5299822472", "529982247250", "", "00000000000", "99999999999"]) expect(isValidCpf(v), v).toBe(false);
  });
});

describe("canonical JSON: surrogates at the edges of their ranges", () => {
  it("accepts a pair and the code units next to the surrogate ranges", () => {
    for (const s of ["𐀀", "􏿿", "퟿", "", "a😀b"]) expect(JSON.parse(canonicalize({ s })).s).toBe(s);
  });
  it("refuses a high surrogate without a low one after it, and a low one on its own", () => {
    for (const s of ["\ud800", "\udbff", "\ud800", "\ud800\udbff", "\ud800a", "\udc00", "\udfff", "a\udfff", "\udc00\ud800"]) expect(() => canonicalize({ s }), JSON.stringify(s)).toThrow("canonical JSON (RFC 8785): a string has a lone surrogate");
  });
});

describe("a signed answer says why it does not verify", () => {
  const at = new Date("2026-11-04T12:00:00Z");
  const setup = async () => {
    const k = await generateAttestationKey();
    const other = await generateAttestationKey();
    const answer: Record<string, unknown> = { credential_id: "c-1", status: "active" };
    answer.attestation = await signAttestation(answer, await importPrivateKey(k.privateKeyPkcs8), k.keyId, "https://issuer.test/v1/verify", at);
    return { k, other, answer };
  };

  it("verifies with the key that signed it, and with the public key derived from the private one", async () => {
    const { k, answer } = await setup();
    expect(await verifyAttestation(answer, k.publicJwk)).toEqual({ valid: true, key_id: k.keyId, signed_at: at.toISOString() });
    const derived = await publicJwkFromPrivate(k.privateKeyPkcs8);
    expect(derived.key_ops).toEqual(["verify"]);
    expect(derived.d).toBeUndefined();
    expect((await verifyAttestation(answer, derived)).valid).toBe(true);
  });

  it("names the missing signature, the changed content, the other key and the bad signature", async () => {
    const { k, other, answer } = await setup();
    const att = answer.attestation as Record<string, unknown>;
    const stamped = { key_id: k.keyId, signed_at: at.toISOString() };
    expect(await verifyAttestation({ credential_id: "c-1", status: "active" }, k.publicJwk)).toEqual({ valid: false, reason: "no ed25519 attestation in the answer" });
    expect(await verifyAttestation({ ...answer, attestation: { ...att, algorithm: "rsa" } }, k.publicJwk)).toEqual({ valid: false, reason: "no ed25519 attestation in the answer" });
    expect(await verifyAttestation({ ...answer, status: "revoked" }, k.publicJwk)).toEqual({ valid: false, reason: "content hash mismatch: the answer was modified", ...stamped });
    expect(await verifyAttestation(answer, other.publicJwk)).toEqual({ valid: false, reason: `signed with key ${k.keyId}, verifying with ${other.keyId}`, ...stamped });
    const later = "2026-11-04T12:00:01.000Z";
    expect(await verifyAttestation({ ...answer, attestation: { ...att, signed_at: later } }, k.publicJwk)).toEqual({ valid: false, reason: "signature does not verify", key_id: k.keyId, signed_at: later });
    const notJson = await verifyAttestation({ ...answer, amount: Number.NaN }, k.publicJwk);
    expect(notJson).toMatchObject({ valid: false, ...stamped });
    expect(notJson.reason).toContain("canonical JSON (RFC 8785)");
  });
});
