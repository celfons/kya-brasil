// Boundaries of the freshness policy. Mutation testing (research/mutation) showed that these edges could be moved
// without any test failing.
import { describe, expect, it } from "vitest";
import { generateAttestationKey, importPrivateKey, signAttestation } from "./attestation.js";
import { type FreshnessPolicyInput, type StatusEvidence, checkFreshness, evidenceFromRevocation, evidenceFromSignedStatus, freshnessPolicy, maxStatusAgeSeconds, valueAtRisk } from "./freshness.js";
import { KyaError } from "./types.js";

const NOW = new Date("2026-11-04T12:00:00Z");
const ago = (seconds: number) => new Date(NOW.getTime() - seconds * 1000).toISOString();
// Test values, not recommendations: the module has no defaults.
const BASE: FreshnessPolicyInput = {
  max_expected_loss: { amount: 1, currency: "BRL" },
  revocation_rate_per_hour: { credential: 1e-4, certificate: 1e-5 },
  require: ["credential"],
  max_age_seconds: 864_000,
  max_clock_skew_seconds: 300,
  unvalued_action: "ceiling",
  past_valid_until: "refuse"
};
const with_ = (over: object) => freshnessPolicy({ ...BASE, ...over } as FreshnessPolicyInput);
const refuses = (over: object | null | string, why: string) => {
  let thrown: unknown;
  try {
    freshnessPolicy((over === null || typeof over === "string" ? over : { ...BASE, ...over }) as FreshnessPolicyInput);
  } catch (e) {
    thrown = e;
  }
  expect(thrown, JSON.stringify(over)).toBeInstanceOf(KyaError);
  expect((thrown as KyaError).code).toBe("INVALID_INPUT");
  expect((thrown as KyaError).message).toContain(why);
};
const credential = (seconds: number, over: Partial<StatusEvidence> = {}): StatusEvidence => ({ kind: "credential", in_force: true, as_of: ago(seconds), ...over });
const check = (evidence: StatusEvidence[], q: object = {}, over: object = {}) => checkFreshness(with_(over), evidence, { now: NOW, ...q });

describe("freshnessPolicy: what it refuses and the last value it accepts", () => {
  it("requires an object with a loss of zero or more in a currency code", () => {
    refuses(null, "expected an object");
    refuses("policy", "expected an object");
    for (const loss of [undefined, null, { currency: "BRL" }, { amount: "1", currency: "BRL" }, { amount: Number.NaN, currency: "BRL" }, { amount: Infinity, currency: "BRL" }, { amount: -0.01, currency: "BRL" }]) refuses({ max_expected_loss: loss }, "max_expected_loss.amount");
    for (const currency of [undefined, 986, "", "B", "BRL!", "!BRL", "B R L"]) refuses({ max_expected_loss: { amount: 1, currency } }, "max_expected_loss.currency");
    expect(with_({ max_expected_loss: { amount: 0, currency: " brl " } }).max_expected_loss).toEqual({ amount: 0, currency: "BRL" });
  });

  it("requires one or more known kinds of evidence, each with its rate", () => {
    for (const require of [undefined, "credential", [], ["other"], ["credential", "other"]]) refuses({ require }, "require must list one or more of credential, certificate");
    expect(with_({ require: ["credential", "certificate", "credential"] }).require).toEqual(["credential", "certificate"]);
    refuses({ revocation_rate_per_hour: { credential: 1e-4, other: 1 } }, 'unknown evidence kind "other"');
    for (const rate of ["1", Number.NaN, Infinity, -1e-9]) refuses({ revocation_rate_per_hour: { credential: rate } }, "revocation_rate_per_hour.credential must be a finite number >= 0");
    expect(with_({ revocation_rate_per_hour: { credential: 0 } }).revocation_rate_per_hour).toEqual({ credential: 0 });
    refuses({ require: ["certificate"], revocation_rate_per_hour: { credential: 1e-4 } }, "revocation_rate_per_hour.certificate is required (or give max_age)");
    expect(with_({ revocation_rate_per_hour: {}, max_age: () => 60 }).require).toEqual(["credential"]);
    refuses({ max_age: 60 }, "max_age must be a function");
  });

  it("requires the ceiling, the tolerance and the two choices, with no default", () => {
    for (const v of [undefined, -1, 1.5, "60", Number.NaN]) {
      refuses({ max_age_seconds: v }, "max_age_seconds is required");
      refuses({ max_clock_skew_seconds: v }, "max_clock_skew_seconds is required");
    }
    expect(with_({ max_age_seconds: 0, max_clock_skew_seconds: 0 })).toMatchObject({ max_age_seconds: 0, max_clock_skew_seconds: 0 });
    for (const v of [undefined, "accept", true]) refuses({ unvalued_action: v }, "unvalued_action is required");
    for (const v of [undefined, "ceiling", true]) refuses({ past_valid_until: v }, "past_valid_until is required");
  });

  it("takes risk values only for action names, each zero or more", () => {
    for (const v of [null, "pay", 5, [], [["pay", 1]]]) refuses({ action_risk_value: v }, "action_risk_value must be an object");
    for (const name of ["Pay", "pay!", "!pay", "p", "p".repeat(33)]) refuses({ action_risk_value: { [name]: 1 } }, "is not a mandate action name");
    for (const v of ["1", null, Number.NaN, Infinity, -1]) refuses({ action_risk_value: { pay: v } }, "action_risk_value.pay must be a finite number >= 0");
    expect(with_({ action_risk_value: { pay: 0, "sign-contract": 700 } }).action_risk_value).toEqual({ pay: 0, "sign-contract": 700 });
  });
});

describe("the value at risk and the age it allows", () => {
  const policy = with_({ action_risk_value: { pay: 700 } });

  it("is the amount, or the risk value of the action by name, or nothing", () => {
    expect(valueAtRisk(policy, 50, "pay")).toBe(50);
    expect(valueAtRisk(policy, 0, "pay")).toBe(0);
    expect(valueAtRisk(policy, undefined, " Pay ")).toBe(700);
    expect(valueAtRisk(policy, undefined, "quote")).toBeUndefined();
    expect(valueAtRisk(policy, undefined, undefined)).toBeUndefined();
    expect(valueAtRisk(policy, undefined, "")).toBeUndefined();
    // A name every object has is not a risk value.
    for (const name of ["constructor", "toString", "hasOwnProperty"]) expect(valueAtRisk(policy, undefined, name)).toBeUndefined();
  });

  it("answers zero, never a negative age, when the caller's function does", () => {
    const answer = (seconds: number) => maxStatusAgeSeconds(with_({ max_age: () => seconds }), "credential", 50);
    expect(answer(-5)).toBe(0);
    expect(answer(-Infinity)).toBe(0);
    expect(answer(Number.NaN)).toBe(0);
    expect(answer(Infinity)).toBe(864_000);
    expect(answer(0)).toBe(0);
    expect(answer(59.9)).toBe(59);
    expect(answer(1e9)).toBe(864_000);
  });
});

describe("checkFreshness at the edge of each rule", () => {
  it("says the age in the unit that fits it", () => {
    const shown = (seconds: number) => check([credential(seconds)]).checks[0]!.detail;
    expect(shown(119)).toBe("credential status is 119 s old; no amount, ceiling applies: at most 10 d");
    expect(shown(120)).toContain("is 2 min old");
    expect(shown(7199)).toContain("is 119 min old");
    expect(shown(7200)).toContain("is 2 h old");
    expect(shown(172_799)).toContain("is 47 h old");
    expect(shown(172_800)).toContain("is 2 d old");
    expect(check([credential(60)], {}, { max_age_seconds: 172_799 }).checks[0]!.detail).toContain("at most 47 h");
  });

  it("accepts evidence exactly as old as the limit and refuses one second more", () => {
    // 1 / (10000 x 1e-4) hours = 3600 s.
    expect(check([credential(3600)], { amount: 10_000 })).toMatchObject({ ok: true, refresh: [] });
    const old = check([credential(3601)], { amount: 10_000 });
    expect(old).toMatchObject({ ok: false, refresh: ["credential"] });
    expect(old.checks[0]).toMatchObject({ ok: false, age_seconds: 3601, max_age_seconds: 3600 });
  });

  it("refuses every kind, and asks for nothing, when the action cannot be judged", () => {
    const both = { require: ["credential", "certificate"] };
    const bad = (q: object, detail: string, over: object = both) => {
      const v = check([credential(60)], q, over);
      expect(v.ok).toBe(false);
      expect(v.refresh).toEqual([]);
      expect(v.checks.map((c) => [c.kind, c.ok, c.detail, c.age_seconds, c.max_age_seconds])).toEqual((over === both ? ["credential", "certificate"] : ["credential"]).map((k) => [k, false, detail, null, 0]));
      return v;
    };
    expect(bad({ now: new Date("x") }, "the verifier's clock is not a valid date").applied.now).toBe("invalid");
    bad({ now: "2026-11-04T12:00:00Z" }, "the verifier's clock is not a valid date");
    for (const amount of ["50", Number.NaN, Infinity, -0.01]) bad({ amount }, "amount is not a finite number >= 0");
    bad({ amount: 50, currency: "usd" }, "loss tolerance is in BRL, operation in USD");
    const refuse = { unvalued_action: "refuse", action_risk_value: { pay: 700 } };
    bad({}, "no amount and no risk value for an unnamed action; the policy refuses actions of unknown value", refuse);
    bad({ action: "Quote" }, 'no amount and no risk value for "quote"; the policy refuses actions of unknown value', refuse);
    // With an amount, or an action the policy gives a value to, the same policy judges the action.
    expect(check([credential(60)], { amount: 0 }, refuse).ok).toBe(true);
    expect(check([credential(60)], { amount: 50, currency: " brl " }, refuse).ok).toBe(true);
    const named = check([credential(60)], { action: "pay" }, refuse);
    expect(named.ok).toBe(true);
    expect(named.applied).toMatchObject({ action: "pay", amount: null, value_at_risk: 700 });
    expect(named.checks[0]!.detail).toContain('for "pay" (risk value 700 BRL)');
  });

  it("judges by the latest evidence, wherever it comes in the list", () => {
    const revokedThenActive = [credential(600, { in_force: false, status: "revoked" }), credential(60)];
    expect(check(revokedThenActive).ok).toBe(true);
    expect(check([...revokedThenActive].reverse()).ok).toBe(true);
    const activeThenRevoked = [credential(600), credential(60, { in_force: false, status: "revoked" })];
    expect(check(activeThenRevoked).ok).toBe(false);
    const late = check([...activeThenRevoked].reverse());
    expect(late).toMatchObject({ ok: false, refresh: [] });
    expect(late.checks[0]!.detail).toBe(`credential is not in force (revoked) as of ${ago(60)}`);
    // Evidence of another kind, or with no readable date, does not count.
    const none = check([{ kind: "certificate", in_force: true, as_of: ago(60) }, credential(60, { as_of: "soon" })]);
    expect(none).toMatchObject({ ok: false, refresh: ["credential"] });
    expect(none.checks[0]).toMatchObject({ detail: "no credential status evidence; no amount, ceiling applies: at most 10 d", age_seconds: null });
  });

  it("holds evidence valid through the instant it expires, and only then asks for a new one", () => {
    const until = (ms: number) => credential(60, { valid_until: new Date(NOW.getTime() + ms).toISOString(), source: "CRL" });
    expect(check([until(0)]).ok).toBe(true);
    const expired = check([until(-1)]);
    expect(expired).toMatchObject({ ok: false, refresh: ["credential"] });
    expect(expired.checks[0]!.detail).toBe(`credential evidence (CRL) expired at ${new Date(NOW.getTime() - 1).toISOString()}`);
    expect(check([until(-1)], {}, { past_valid_until: "accept" }).ok).toBe(true);
    // No valid_until, or one that is not a date, is not an expiry.
    expect(check([credential(60)]).ok).toBe(true);
    expect(check([credential(60, { valid_until: "never" })]).ok).toBe(true);
  });

  it("tolerates evidence dated ahead of the clock up to the skew, to the millisecond", () => {
    const ahead = (ms: number) => credential(0, { as_of: new Date(NOW.getTime() + ms).toISOString() });
    expect(check([ahead(300_000)])).toMatchObject({ ok: true, checks: [{ age_seconds: 0 }] });
    const future = check([ahead(300_001)]);
    expect(future).toMatchObject({ ok: false, refresh: [] });
    expect(future.checks[0]!.detail).toContain("beyond the 300 s tolerance");
  });
});

describe("evidence builders at their edges", () => {
  it("reads a CRL lookup: in force unless revoked, with the reason when the list gives one", () => {
    const lookup = { revoked_at: null, crl_this_update: ago(3600), crl_next_update: ago(-3600) };
    expect(evidenceFromRevocation({ ...lookup, revoked: false, reason: null })).toEqual({ kind: "certificate", in_force: true, as_of: ago(3600), valid_until: ago(-3600), source: "CRL", status: "not revoked" });
    expect(evidenceFromRevocation({ ...lookup, revoked: true, reason: "keyCompromise" }, "AC Teste")).toMatchObject({ in_force: false, source: "AC Teste", status: "keyCompromise" });
    expect(evidenceFromRevocation({ ...lookup, revoked: true, reason: null })).toMatchObject({ in_force: false, status: "revoked" });
  });

  it("reads a signed status only when it is an object about this credential, with a status, that verifies", async () => {
    const k = await generateAttestationKey();
    const key = await importPrivateKey(k.privateKeyPkcs8);
    const signed = async (status: unknown) => {
      const answer: Record<string, unknown> = { credential_id: "c-1", status };
      answer.attestation = await signAttestation(answer, key, k.keyId, "https://issuer.test/v1/verify", new Date(ago(120)));
      return answer;
    };
    expect(await evidenceFromSignedStatus(await signed("active"), k.publicJwk, "c-1")).toEqual({ kind: "credential", in_force: true, as_of: ago(120), source: "issuer signed status", status: "active" });
    expect(await evidenceFromSignedStatus(await signed("revoked"), k.publicJwk, "c-1")).toMatchObject({ in_force: false, status: "revoked" });
    expect(await evidenceFromSignedStatus(await signed("suspended"), k.publicJwk, "c-1")).toMatchObject({ in_force: false, status: "suspended" });
    for (const answer of [null, undefined, "active", 5]) await expect(evidenceFromSignedStatus(answer as never, k.publicJwk, "c-1")).rejects.toThrow("signed status: expected an object");
    await expect(evidenceFromSignedStatus(await signed(1), k.publicJwk, "c-1")).rejects.toThrow("signed status has no status");
    await expect(evidenceFromSignedStatus({ credential_id: "c-1", status: "active" }, k.publicJwk, "c-1")).rejects.toThrow(/^signed status does not verify: /);
  });
});
