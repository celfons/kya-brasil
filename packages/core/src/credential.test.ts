import { describe, expect, it } from "vitest";
import { generateAttestationKey, importPrivateKey } from "./attestation";
import { buildCredential, effectiveStatus, principalDecision, signCredential, verifyCredentialSignature } from "./credential";
import type { KybSnapshot } from "./types";

const kyb: KybSnapshot = { risk_level: "low", risk_score: 5, registration_status: "ATIVA", active_sanctions: 0, forced_labor: false, federal_debt_brl: null, active_embargoes: 0, red_flags: [], checked_at: "2026-10-12T00:00:00Z" };

describe("credential", () => {
  it("builds, signs and verifies; expiry never outlives the mandate", async () => {
    const key = await generateAttestationKey();
    const c = buildCredential({ credential_id: "cred-1", agent: { kind: "evm", id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" }, cnpj: "11.222.333/0001-81", legal_name: "ACME LTDA", registration_status: "ATIVA", certificate: { sha256: "ab", subject: "CN=ACME LTDA:11222333000181", issuer: "CN=AC Teste", signed_at: "2026-10-12T00:00:00Z" }, mandate: { actions: ["pay"], valid_until: "2026-11-01T00:00:00Z" }, kyb, issuer: "https://kya.test", now: new Date("2026-10-12T00:00:00Z") });
    expect(c.expires_at).toBe("2026-11-01T00:00:00.000Z");
    expect(c.principal.cnpj_formatted).toBe("11.222.333/0001-81");
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

  it("an active credential past expires_at reads as expired", () => {
    expect(effectiveStatus({ status: "active", expires_at: "2026-01-01T00:00:00Z" }, new Date("2026-10-12T00:00:00Z"))).toBe("expired");
    expect(effectiveStatus({ status: "revoked", expires_at: "2099-01-01T00:00:00Z" })).toBe("revoked");
  });
});
