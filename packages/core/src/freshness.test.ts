import { describe, expect, it } from "vitest";
import { generateAttestationKey, importPrivateKey, signAttestation } from "./attestation.js";
import { type FreshnessPolicyInput, type StatusEvidence, checkFreshAction, checkFreshness, evidenceFromRevocation, evidenceFromSignedStatus, freshnessPolicy, maxStatusAgeSeconds } from "./freshness.js";
import { validateMandate } from "./mandate.js";

const NOW = new Date("2026-11-04T12:00:00Z");
const ago = (seconds: number) => new Date(NOW.getTime() - seconds * 1000).toISOString();

// Every value is the caller's: the module has no defaults. These are test values, not recommendations.
// L = 1 BRL of expected loss per action, λ = 1e-4 per hour: max age = 1 / (v × 1e-4) hours = 10 000 / v hours.
const BASE: FreshnessPolicyInput = {
  max_expected_loss: { amount: 1, currency: "brl" },
  revocation_rate_per_hour: { credential: 1e-4, certificate: 1e-5 },
  require: ["credential"],
  max_age_seconds: 86_400,
  max_clock_skew_seconds: 300,
  unvalued_action: "ceiling",
  past_valid_until: "refuse"
};
const with_ = (over: Partial<FreshnessPolicyInput>) => freshnessPolicy({ ...BASE, ...over });
const policy = freshnessPolicy(BASE);
const credentialAt = (seconds: number, in_force = true): StatusEvidence => ({ kind: "credential", in_force, as_of: ago(seconds), status: in_force ? "active" : "revoked" });

describe("maxStatusAgeSeconds: L / (v × λ), capped by the caller's ceiling", () => {
  it("shrinks in inverse proportion to the amount", () => {
    expect(maxStatusAgeSeconds(policy, "credential", 1_000_000)).toBe(36); // 0.01 h
    expect(maxStatusAgeSeconds(policy, "credential", 100_000)).toBe(360);
    expect(maxStatusAgeSeconds(policy, "credential", 10_000)).toBe(3600);
  });
  it("is capped by max_age_seconds for small, zero or unknown amounts", () => {
    expect(maxStatusAgeSeconds(policy, "credential", 50)).toBe(86_400);
    expect(maxStatusAgeSeconds(policy, "credential", 0)).toBe(86_400);
    expect(maxStatusAgeSeconds(policy, "credential")).toBe(86_400);
    expect(maxStatusAgeSeconds(with_({ max_age_seconds: 120 }), "credential", 50)).toBe(120);
  });
  it("uses the rate of each kind", () => {
    expect(maxStatusAgeSeconds(policy, "certificate", 100_000)).toBe(3600);
  });
  it("takes a caller-supplied function, clamped, failing closed on non-finite results", () => {
    const steps = with_({ max_expected_loss: { amount: 0, currency: "BRL" }, revocation_rate_per_hour: {}, max_age: ({ amount }) => ((amount ?? 0) <= 500 ? 3600 : 60), max_age_seconds: 1800 });
    expect(maxStatusAgeSeconds(steps, "credential", 100)).toBe(1800);
    expect(maxStatusAgeSeconds(steps, "credential", 900)).toBe(60);
    const broken = with_({ revocation_rate_per_hour: {}, max_age: () => Number.NaN });
    expect(maxStatusAgeSeconds(broken, "credential", 10)).toBe(0);
  });
});

describe("freshnessPolicy: no defaults, every risk value is required", () => {
  const without = (k: keyof FreshnessPolicyInput) => {
    const input: Record<string, unknown> = { ...BASE };
    delete input[k];
    return () => freshnessPolicy(input as unknown as FreshnessPolicyInput);
  };
  it("refuses a policy missing any of them", () => {
    expect(without("require")).toThrow(/require/);
    expect(without("max_age_seconds")).toThrow(/max_age_seconds is required/);
    expect(without("max_clock_skew_seconds")).toThrow(/max_clock_skew_seconds is required/);
    expect(without("unvalued_action")).toThrow(/unvalued_action is required/);
    expect(without("past_valid_until")).toThrow(/past_valid_until is required/);
    expect(() => with_({ revocation_rate_per_hour: {} })).toThrow(/revocation_rate_per_hour.credential is required/);
  });
  it("refuses malformed values, and puts no upper bound of its own", () => {
    expect(() => with_({ max_expected_loss: { amount: -1, currency: "BRL" } })).toThrow(/max_expected_loss/);
    expect(() => with_({ revocation_rate_per_hour: { credential: Number.POSITIVE_INFINITY } })).toThrow(/finite/);
    expect(() => with_({ max_age_seconds: -1 })).toThrow(/max_age_seconds/);
    expect(() => with_({ max_clock_skew_seconds: 1.5 })).toThrow(/max_clock_skew_seconds/);
    expect(() => with_({ require: [] })).toThrow(/require/);
    expect(with_({ max_age_seconds: 365 * 86_400, max_clock_skew_seconds: 7200 }).max_age_seconds).toBe(365 * 86_400);
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
    const v = checkFreshness(with_({ require: ["credential", "certificate"] }), [credentialAt(10)], { amount: 50, now: NOW });
    expect(v.ok).toBe(false);
    expect(v.refresh).toEqual(["certificate"]);
  });
  it("refuses evidence dated in the future beyond the caller's clock skew, and accepts it within", () => {
    expect(checkFreshness(policy, [credentialAt(-600)], { amount: 50, now: NOW }).ok).toBe(false);
    expect(checkFreshness(policy, [credentialAt(-60)], { amount: 50, now: NOW }).ok).toBe(true);
    expect(checkFreshness(with_({ max_clock_skew_seconds: 0 }), [credentialAt(-60)], { amount: 50, now: NOW }).ok).toBe(false);
  });
  it("fails closed on another currency, a bad amount or a missing or bad clock", () => {
    expect(checkFreshness(policy, [credentialAt(1)], { amount: 50, currency: "USD", now: NOW }).checks[0]!.detail).toMatch(/in BRL, operation in USD/);
    expect(checkFreshness(policy, [credentialAt(1)], { amount: Number.NaN, now: NOW }).ok).toBe(false);
    expect(checkFreshness(policy, [credentialAt(1)], { amount: 50, now: new Date(Number.NaN) }).ok).toBe(false);
    expect(checkFreshness(policy, [credentialAt(1)], { amount: 50 } as { amount: number; now: Date }).ok).toBe(false);
  });
  it("records the policy and clock applied, for disputes", () => {
    const v = checkFreshness(policy, [credentialAt(1)], { amount: 50, currency: "BRL", now: NOW });
    expect(v.applied).toMatchObject({ now: NOW.toISOString(), amount: 50, currency: "BRL", max_expected_loss: { amount: 1, currency: "BRL" }, max_age_seconds: 86_400, max_clock_skew_seconds: 300, unvalued_action: "ceiling", past_valid_until: "refuse", custom_max_age: false });
  });
});

describe("evidence builders", () => {
  const crlEvidence = () => evidenceFromRevocation({ revoked: false, revoked_at: null, reason: null, crl_this_update: ago(3600), crl_next_update: ago(60) });
  it("turns a CRL lookup into certificate evidence; past nextUpdate it is refused or judged by age, as the caller chose", () => {
    expect(crlEvidence()).toMatchObject({ kind: "certificate", in_force: true });
    const refuse = checkFreshness(with_({ require: ["certificate"] }), [crlEvidence()], { amount: 50, now: NOW });
    expect(refuse.ok).toBe(false);
    expect(refuse.checks[0]!.detail).toMatch(/expired at/);
    const byAge = with_({ require: ["certificate"], past_valid_until: "accept" });
    expect(checkFreshness(byAge, [crlEvidence()], { amount: 50, now: NOW }).ok).toBe(true); // 1 h old, 24 h allowed
    expect(checkFreshness(byAge, [crlEvidence()], { amount: 1_000_000, now: NOW }).ok).toBe(false); // 1 h old, 6 min allowed
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

describe("any action, not only payments", () => {
  const p = with_({ action_risk_value: { sign_contract: 100_000, read_data: 50 } });
  it("uses the risk value the verifier gives an action that has no amount", () => {
    expect(maxStatusAgeSeconds(p, "credential", undefined, "sign_contract")).toBe(360);
    expect(maxStatusAgeSeconds(p, "credential", undefined, "read_data")).toBe(86_400);
    const v = checkFreshness(p, [credentialAt(600)], { action: "sign_contract", now: NOW });
    expect(v.ok).toBe(false);
    expect(v.checks[0]!.detail).toMatch(/for "sign_contract" \(risk value 100000 BRL\): at most 6 min/);
    expect(v.applied).toMatchObject({ action: "sign_contract", amount: null, value_at_risk: 100_000 });
  });
  it("prefers the amount when the action has one", () => {
    expect(maxStatusAgeSeconds(p, "credential", 50, "sign_contract")).toBe(86_400);
  });
  it("for an action of unknown value, does what the caller chose: the ceiling, or refuse", () => {
    const ceiling = checkFreshness(p, [credentialAt(60)], { action: "call_api", now: NOW });
    expect(ceiling.ok).toBe(true);
    expect(ceiling.checks[0]!.detail).toMatch(/no amount and no risk value for "call_api", ceiling applies/);
    expect(ceiling.applied.value_at_risk).toBeNull();
    const refuse = checkFreshness(with_({ action_risk_value: { read_data: 50 }, unvalued_action: "refuse" }), [credentialAt(60)], { action: "call_api", now: NOW });
    expect(refuse.ok).toBe(false);
    expect(refuse.checks[0]!.detail).toMatch(/refuses actions of unknown value/);
  });
  it("passes the action to a custom max_age", () => {
    const custom = with_({ revocation_rate_per_hour: {}, max_age: ({ action }) => (action === "sign_contract" ? 60 : 3600) });
    expect(maxStatusAgeSeconds(custom, "credential", undefined, "SIGN_CONTRACT")).toBe(60);
    expect(maxStatusAgeSeconds(custom, "credential", undefined, "read_data")).toBe(3600);
  });
  it("checkFreshAction evaluates a non-monetary action against the mandate and its risk value", () => {
    const mandate = validateMandate({ actions: ["sign_contract", "read_data"] });
    expect(checkFreshAction(mandate, { action: "sign_contract", now: NOW }, { policy: p, evidence: [credentialAt(60)] }).allowed).toBe(true);
    expect(checkFreshAction(mandate, { action: "sign_contract", now: NOW }, { policy: p, evidence: [credentialAt(3600)] }).allowed).toBe(false);
  });
  it("refuses risk values that would fail open", () => {
    expect(() => with_({ action_risk_value: { sign: -1 } })).toThrow(/finite number >= 0/);
    expect(() => with_({ action_risk_value: { "Sign Contract": 1 } })).toThrow(/not a mandate action name/);
  });
});
