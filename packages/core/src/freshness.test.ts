import { describe, expect, it } from "vitest";
import { generateAttestationKey, importPrivateKey, signAttestation } from "./attestation.js";
import { type StatusEvidence, checkFreshAction, checkFreshness, evidenceFromRevocation, evidenceFromSignedStatus, freshnessPolicy, maxStatusAgeSeconds } from "./freshness.js";
import { validateMandate } from "./mandate.js";

const NOW = new Date("2026-11-04T12:00:00Z");
const ago = (seconds: number) => new Date(NOW.getTime() - seconds * 1000).toISOString();

// L = 1 BRL of expected loss per action, λ = 1e-4 per hour: max age = 1 / (v × 1e-4) hours = 10 000 / v hours.
const policy = freshnessPolicy({ max_expected_loss: { amount: 1, currency: "brl" }, revocation_rate_per_hour: { credential: 1e-4, certificate: 1e-5 } });
const credentialAt = (seconds: number, in_force = true): StatusEvidence => ({ kind: "credential", in_force, as_of: ago(seconds), status: in_force ? "active" : "revoked" });

describe("maxStatusAgeSeconds: L / (v × λ), capped", () => {
  it("shrinks in inverse proportion to the amount", () => {
    expect(maxStatusAgeSeconds(policy, "credential", 1_000_000)).toBe(36); // 0.01 h
    expect(maxStatusAgeSeconds(policy, "credential", 100_000)).toBe(360);
    expect(maxStatusAgeSeconds(policy, "credential", 10_000)).toBe(3600);
  });
  it("is capped by max_age_seconds (default one day) for small, zero or unknown amounts", () => {
    expect(maxStatusAgeSeconds(policy, "credential", 50)).toBe(86_400);
    expect(maxStatusAgeSeconds(policy, "credential", 0)).toBe(86_400);
    expect(maxStatusAgeSeconds(policy, "credential")).toBe(86_400);
  });
  it("uses the rate of each kind", () => {
    expect(maxStatusAgeSeconds(policy, "certificate", 100_000)).toBe(3600);
  });
  it("takes a caller-supplied function, clamped, failing closed on non-finite results", () => {
    const steps = freshnessPolicy({ max_expected_loss: { amount: 0, currency: "BRL" }, revocation_rate_per_hour: {}, max_age: ({ amount }) => ((amount ?? 0) <= 500 ? 3600 : 60), max_age_seconds: 1800 });
    expect(maxStatusAgeSeconds(steps, "credential", 100)).toBe(1800);
    expect(maxStatusAgeSeconds(steps, "credential", 900)).toBe(60);
    const broken = freshnessPolicy({ max_expected_loss: { amount: 1, currency: "BRL" }, revocation_rate_per_hour: {}, max_age: () => Number.NaN });
    expect(maxStatusAgeSeconds(broken, "credential", 10)).toBe(0);
  });
});

describe("freshnessPolicy validation", () => {
  it("refuses inputs that would fail open", () => {
    expect(() => freshnessPolicy({ max_expected_loss: { amount: -1, currency: "BRL" }, revocation_rate_per_hour: { credential: 1e-4 } })).toThrow(/max_expected_loss/);
    expect(() => freshnessPolicy({ max_expected_loss: { amount: 1, currency: "BRL" }, revocation_rate_per_hour: {} })).toThrow(/revocation_rate_per_hour.credential is required/);
    expect(() => freshnessPolicy({ max_expected_loss: { amount: 1, currency: "BRL" }, revocation_rate_per_hour: { credential: Number.POSITIVE_INFINITY } })).toThrow(/finite/);
    expect(() => freshnessPolicy({ max_expected_loss: { amount: 1, currency: "BRL" }, revocation_rate_per_hour: { credential: 1e-4 }, max_age_seconds: 91 * 86_400 })).toThrow(/max_age_seconds/);
    expect(() => freshnessPolicy({ max_expected_loss: { amount: 1, currency: "BRL" }, revocation_rate_per_hour: { credential: 1e-4 }, require: [] })).toThrow(/require/);
  });
});

describe("checkFreshness", () => {
  it("accepts evidence younger than the limit for the amount and refuses older, asking for a refresh", () => {
    const ok = checkFreshness(policy, [credentialAt(300)], { amount: 100_000, currency: "BRL", now: NOW });
    expect(ok.ok).toBe(true);
    const stale = checkFreshness(policy, [credentialAt(600)], { amount: 100_000, currency: "BRL", now: NOW });
    expect(stale.ok).toBe(false);
    expect(stale.refresh).toEqual(["credential"]);
    expect(stale.checks[0]!.detail).toMatch(/10 min old; for 100000 BRL: at most 6 min/);
  });
  it("lets the same old evidence pass for a small amount (works offline)", () => {
    expect(checkFreshness(policy, [credentialAt(6 * 3600)], { amount: 50, currency: "BRL", now: NOW }).ok).toBe(true);
  });
  it("uses the freshest statement: a later revocation wins over an earlier active", () => {
    const v = checkFreshness(policy, [credentialAt(60), credentialAt(10, false)], { amount: 50, now: NOW });
    expect(v.ok).toBe(false);
    expect(v.checks[0]!.detail).toMatch(/not in force \(revoked\)/);
    expect(v.refresh).toEqual([]);
  });
  it("refuses missing evidence for a required kind", () => {
    const p = freshnessPolicy({ max_expected_loss: { amount: 1, currency: "BRL" }, revocation_rate_per_hour: { credential: 1e-4, certificate: 1e-5 }, require: ["credential", "certificate"] });
    const v = checkFreshness(p, [credentialAt(10)], { amount: 50, now: NOW });
    expect(v.ok).toBe(false);
    expect(v.refresh).toEqual(["certificate"]);
  });
  it("refuses evidence dated in the future beyond the clock skew, and accepts it within", () => {
    expect(checkFreshness(policy, [credentialAt(-600)], { amount: 50, now: NOW }).ok).toBe(false);
    expect(checkFreshness(policy, [credentialAt(-60)], { amount: 50, now: NOW }).ok).toBe(true);
  });
  it("fails closed on another currency, a bad amount or a bad clock", () => {
    expect(checkFreshness(policy, [credentialAt(1)], { amount: 50, currency: "USD", now: NOW }).checks[0]!.detail).toMatch(/in BRL, operation in USD/);
    expect(checkFreshness(policy, [credentialAt(1)], { amount: Number.NaN, now: NOW }).ok).toBe(false);
    expect(checkFreshness(policy, [credentialAt(1)], { amount: 50, now: new Date(Number.NaN) }).ok).toBe(false);
  });
  it("records the policy and clock applied, for disputes", () => {
    const v = checkFreshness(policy, [credentialAt(1)], { amount: 50, currency: "BRL", now: NOW });
    expect(v.applied).toMatchObject({ now: NOW.toISOString(), amount: 50, currency: "BRL", max_expected_loss: { amount: 1, currency: "BRL" }, max_age_seconds: 86_400, custom_max_age: false });
  });
});

describe("evidence builders", () => {
  it("turns a CRL lookup into certificate evidence, honouring nextUpdate", () => {
    const e = evidenceFromRevocation({ revoked: false, revoked_at: null, reason: null, crl_this_update: ago(3600), crl_next_update: ago(60) });
    expect(e).toMatchObject({ kind: "certificate", in_force: true });
    const p = freshnessPolicy({ max_expected_loss: { amount: 1, currency: "BRL" }, revocation_rate_per_hour: { certificate: 1e-5 }, require: ["certificate"] });
    const v = checkFreshness(p, [e], { amount: 50, now: NOW });
    expect(v.ok).toBe(false);
    expect(v.checks[0]!.detail).toMatch(/expired at/);
  });
  it("accepts an issuer-signed status for the right credential only, dated by the signature", async () => {
    const k = await generateAttestationKey();
    const key = await importPrivateKey(k.privateKeyPkcs8);
    const answer: Record<string, unknown> = { credential_id: "c-1", status: "active", allowed: true };
    answer.attestation = await signAttestation(answer, key, k.keyId, "https://issuer.test/v1/verify", new Date(ago(120)));
    const e = await evidenceFromSignedStatus(answer, k.publicJwk, "c-1");
    expect(e).toMatchObject({ kind: "credential", in_force: true, as_of: ago(120) });
    await expect(evidenceFromSignedStatus(answer, k.publicJwk, "c-2")).rejects.toThrow(/not c-2/);
    await expect(evidenceFromSignedStatus({ ...answer, status: "revoked" }, k.publicJwk, "c-1")).rejects.toThrow(/does not verify/);
  });
});

describe("checkFreshAction", () => {
  it("allows only when the mandate and the freshness both pass", () => {
    const mandate = validateMandate({ actions: ["buy"], max_per_operation: { amount: 200_000, currency: "BRL" } });
    const q = { action: "buy", amount: 100_000, currency: "BRL", now: NOW };
    expect(checkFreshAction(mandate, q, { policy, evidence: [credentialAt(60)] }).allowed).toBe(true);
    const r = checkFreshAction(mandate, q, { policy, evidence: [credentialAt(3600)] });
    expect(r.allowed).toBe(false);
    expect(r.mandate.allowed).toBe(true);
    expect(r.freshness.refresh).toEqual(["credential"]);
  });
});
