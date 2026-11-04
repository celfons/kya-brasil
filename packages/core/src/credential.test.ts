import { describe, expect, it } from "vitest";
import { generateAttestationKey, importPrivateKey } from "./attestation.js";
import { buildCredential, credentialExpiry, effectiveStatus, principalDecision, signCredential, verifyCredentialSignature } from "./credential.js";
import type { KybSnapshot } from "./types.js";

const kyb: KybSnapshot = { risk_level: "low", risk_score: 5, registration_status: "ATIVA", active_sanctions: 0, forced_labor: false, federal_debt_brl: null, active_embargoes: 0, red_flags: [], checked_at: "2026-10-12T00:00:00Z" };

describe("credential", () => {
  it("builds, signs and verifies; expiry never outlives the mandate", async () => {
    const key = await generateAttestationKey();
    const c = buildCredential({ credential_id: "cred-1", agent: { kind: "evm", id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" }, cnpj: "11.222.333/0001-81", legal_name: "ACME LTDA", registration_status: "ATIVA", certificate: { sha256: "ab", subject: "CN=ACME LTDA:11222333000181", issuer: "CN=AC Teste", signed_at: "2026-10-12T00:00:00Z", not_after: "2027-10-12T00:00:00Z" }, mandate: { actions: ["pay"], valid_until: "2026-11-01T00:00:00Z" }, ttl_seconds: 90 * 86400, kyb, issuer: "https://kya.test", now: new Date("2026-10-12T00:00:00Z") });
    expect(c.expires_at).toBe("2026-11-01T00:00:00.000Z");
    expect((c.principal as { cnpj_formatted: string }).cnpj_formatted).toBe("11.222.333/0001-81");
    const signed = await signCredential(c, await importPrivateKey(key.privateKeyPkcs8), key.keyId);
    expect((await verifyCredentialSignature(signed, key.publicJwk)).valid).toBe(true);
    expect((await verifyCredentialSignature({ ...signed, status: "revoked" }, key.publicJwk)).valid).toBe(false);
  });

  it("only the registration status decides (D-15): sanctions and risk are the verifier's call", () => {
    expect(principalDecision("ATIVA")).toEqual({ ok: true, reason: null });
    expect(principalDecision("BAIXADA").reason).toMatch(/BAIXADA/);
    // D-24: unknown is not "not active"
    expect(principalDecision("UNVERIFIED")).toEqual({ ok: true, reason: null });
    expect(principalDecision("NOT_CHECKED")).toEqual({ ok: true, reason: null });
    expect(principalDecision("INAPTA").ok).toBe(false);
  });

  it("D-35: the lifetime is the caller's, and the credential never outlives the certificate nor the mandate", () => {
    const now = new Date("2026-10-12T00:00:00Z");
    const base = { now, mandate: {}, certificate_not_after: "2027-10-12T00:00:00Z" };
    expect(credentialExpiry({ ...base, ttl_seconds: 3600 }).toISOString()).toBe("2026-10-12T01:00:00.000Z");
    expect(credentialExpiry({ ...base, ttl_seconds: 10 * 365 * 86400 }).toISOString()).toBe("2027-10-12T00:00:00.000Z");
    expect(credentialExpiry({ ...base, ttl_seconds: 10 * 365 * 86400, mandate: { valid_until: "2027-01-01T00:00:00Z" } }).toISOString()).toBe("2027-01-01T00:00:00.000Z");
    for (const ttl of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, undefined as unknown as number]) expect(() => credentialExpiry({ ...base, ttl_seconds: ttl })).toThrow(/ttl_seconds/);
    expect(() => credentialExpiry({ ...base, ttl_seconds: 60, certificate_not_after: "2026-10-11T00:00:00Z" })).toThrow(/expired/);
    expect(() => credentialExpiry({ ...base, ttl_seconds: 60, certificate_not_after: "x" })).toThrow(/not_after/);
  });

  it("an active credential past expires_at reads as expired", () => {
    expect(effectiveStatus({ status: "active", expires_at: "2026-01-01T00:00:00Z" }, new Date("2026-10-12T00:00:00Z"))).toBe("expired");
    expect(effectiveStatus({ status: "revoked", expires_at: "2099-01-01T00:00:00Z" })).toBe("revoked");
  });
});
