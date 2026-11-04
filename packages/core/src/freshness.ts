/**
 * Status freshness proportional to what is at stake (D-32, SPEC section 18).
 *
 * A verifier working offline holds evidence of status that is some time old: an issuer answer signed at a
 * given instant (the credential's status), or a CRL issued at a given instant (the e-CNPJ / e-CPF
 * certificate's status). Following Rivest (1998), the recency requirement is set by whoever accepts the
 * action and runs the risk, not by the issuer: this module turns the verifier's loss tolerance into a
 * maximum evidence age that shrinks as the amount grows, and refuses older evidence.
 *
 * Expected loss of accepting an action of value v on evidence of age t, when status changes at a rate of
 * λ per hour: v × λ × t. Keeping it under the tolerance L gives the default maximum age
 *
 *     max_age(v) = L / (v × λ)   hours, capped by max_age_seconds.
 *
 * Any action, not only payments: for an action with no amount (sign a document, read data, call an API) the
 * verifier assigns a risk value per action (`action_risk_value`), or decides the age itself (`max_age`).
 *
 * Pure functions, no network: the caller obtains the evidence (cache, CRL download, an issuer answer the
 * agent staples to its request) and passes the clock it trusts.
 */
import { verifyAttestation } from "./attestation.js";
import { type ActionQuery, type ActionVerdict, checkAction } from "./mandate.js";
import { KyaError, type Mandate } from "./types.js";
import type { RevocationStatus } from "./revocation.js";

/** What a piece of evidence is about: the KYA credential (issuer status) or the ICP-Brasil certificate (CRL). */
export type EvidenceKind = "credential" | "certificate";

export interface StatusEvidence {
  kind: EvidenceKind;
  /** True when the evidence says the subject is in force: credential `active`, certificate not on the CRL. */
  in_force: boolean;
  /** Instant at which the status was true: the issuer's `attestation.signed_at`, or the CRL's thisUpdate. */
  as_of: string;
  /** Instant after which the evidence must not be used at all (a CRL's nextUpdate). */
  valid_until?: string | null;
  /** Free text for the verdict, e.g. "issuer verdict" or "CRL of AC X". */
  source?: string;
  /** Status as stated by the evidence, for the verdict ("active", "revoked", "certificateHold", ...). */
  status?: string;
}

export const FRESHNESS_DEFAULT_MAX_AGE_SECONDS = 86_400;
export const FRESHNESS_LIMIT_MAX_AGE_SECONDS = 90 * 86_400;
export const FRESHNESS_DEFAULT_CLOCK_SKEW_SECONDS = 300;

export interface FreshnessPolicyInput {
  /** L: the expected loss the verifier accepts per action, in the currency of the amounts it checks. */
  max_expected_loss: { amount: number; currency: string };
  /** λ: probability per hour that a subject in force stops being so, per kind of evidence. */
  revocation_rate_per_hour: Partial<Record<EvidenceKind, number>>;
  /** Kinds of evidence an action needs. Default ["credential"]. */
  require?: EvidenceKind[];
  /** Ceiling on the evidence age, whatever the amount. Default 86400 (one day), at most 90 days. */
  max_age_seconds?: number;
  /** Tolerance for evidence dated after the verifier's clock. Default 300, at most 3600. */
  max_clock_skew_seconds?: number;
  /**
   * Value at risk, in the policy's currency, of actions that carry no amount (`sign`, `read`, `call`...),
   * keyed by action name. Used only when the action has no amount. An action with neither falls back to
   * the ceiling, so list every non-monetary action you accept.
   */
  action_risk_value?: Record<string, number>;
  /**
   * Replaces the default formula. Receives the value at risk (the amount, or the action's risk value; undefined
   * when there is neither), the action and the kind; returns seconds. The result is clamped to
   * [0, max_age_seconds]; anything not finite counts as 0.
   */
  max_age?: (p: { amount: number | undefined; currency: string; kind: EvidenceKind; action?: string }) => number;
}

export interface FreshnessPolicy {
  max_expected_loss: { amount: number; currency: string };
  revocation_rate_per_hour: Partial<Record<EvidenceKind, number>>;
  require: EvidenceKind[];
  max_age_seconds: number;
  max_clock_skew_seconds: number;
  action_risk_value: Record<string, number>;
  max_age?: FreshnessPolicyInput["max_age"];
}

const KINDS: EvidenceKind[] = ["credential", "certificate"];
const CURRENCY = /^[A-Z0-9]{2,10}$/;
const ACTION = /^[a-z][a-z0-9_-]{1,31}$/;

function bad(message: string): never {
  throw new KyaError("INVALID_INPUT", `freshness policy: ${message}`);
}

/** Validates and normalizes a policy. Throws INVALID_INPUT on anything that would make it fail open. */
export function freshnessPolicy(input: FreshnessPolicyInput): FreshnessPolicy {
  if (!input || typeof input !== "object") bad("expected an object");
  const loss = input.max_expected_loss;
  if (!loss || typeof loss.amount !== "number" || !Number.isFinite(loss.amount) || loss.amount < 0) bad("max_expected_loss.amount must be a finite number >= 0");
  const currency = typeof loss.currency === "string" ? loss.currency.trim().toUpperCase() : "";
  if (!CURRENCY.test(currency)) bad("max_expected_loss.currency must match ^[A-Z0-9]{2,10}$");

  const require = input.require ?? ["credential"];
  if (!Array.isArray(require) || !require.length || require.some((k) => !KINDS.includes(k))) bad(`require must list one or more of ${KINDS.join(", ")}`);

  const rates: Partial<Record<EvidenceKind, number>> = {};
  for (const [k, v] of Object.entries(input.revocation_rate_per_hour ?? {})) {
    if (!KINDS.includes(k as EvidenceKind)) bad(`unknown evidence kind "${k}" in revocation_rate_per_hour`);
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0) bad(`revocation_rate_per_hour.${k} must be a finite number >= 0`);
    rates[k as EvidenceKind] = v;
  }
  if (!input.max_age) for (const k of require) if (rates[k] === undefined) bad(`revocation_rate_per_hour.${k} is required (or give max_age)`);

  const ceiling = input.max_age_seconds ?? FRESHNESS_DEFAULT_MAX_AGE_SECONDS;
  if (!Number.isInteger(ceiling) || ceiling < 0 || ceiling > FRESHNESS_LIMIT_MAX_AGE_SECONDS) bad(`max_age_seconds must be an integer in 0..${FRESHNESS_LIMIT_MAX_AGE_SECONDS}`);
  const skew = input.max_clock_skew_seconds ?? FRESHNESS_DEFAULT_CLOCK_SKEW_SECONDS;
  if (!Number.isInteger(skew) || skew < 0 || skew > 3600) bad("max_clock_skew_seconds must be an integer in 0..3600");
  if (input.max_age !== undefined && typeof input.max_age !== "function") bad("max_age must be a function");
  const values: Record<string, number> = {};
  if (input.action_risk_value !== undefined) {
    if (!input.action_risk_value || typeof input.action_risk_value !== "object" || Array.isArray(input.action_risk_value)) bad("action_risk_value must be an object of action -> value");
    for (const [a, v] of Object.entries(input.action_risk_value)) {
      if (!ACTION.test(a)) bad(`action_risk_value: "${a}" is not a mandate action name (^[a-z][a-z0-9_-]{1,31}$)`);
      if (typeof v !== "number" || !Number.isFinite(v) || v < 0) bad(`action_risk_value.${a} must be a finite number >= 0`);
      values[a] = v;
    }
  }

  return { max_expected_loss: { amount: loss.amount, currency }, revocation_rate_per_hour: rates, require: [...new Set(require)], max_age_seconds: ceiling, max_clock_skew_seconds: skew, action_risk_value: values, max_age: input.max_age };
}

/** The value at risk of an action: its amount, or else the risk value the policy gives its name. */
export function valueAtRisk(policy: FreshnessPolicy, amount?: number, action?: string): number | undefined {
  if (amount !== undefined) return amount;
  const a = action?.trim().toLowerCase();
  return a && Object.hasOwn(policy.action_risk_value, a) ? policy.action_risk_value[a] : undefined;
}

/**
 * Maximum evidence age, in whole seconds, for an action of `amount` (in the policy's currency) or, with no
 * amount, of the risk value the policy assigns to `action`.
 */
export function maxStatusAgeSeconds(policy: FreshnessPolicy, kind: EvidenceKind, amount?: number, action?: string): number {
  const ceiling = policy.max_age_seconds;
  const value = valueAtRisk(policy, amount, action);
  let seconds: number;
  if (policy.max_age) {
    seconds = policy.max_age({ amount: value, currency: policy.max_expected_loss.currency, kind, action: action?.trim().toLowerCase() || undefined });
  } else {
    const rate = policy.revocation_rate_per_hour[kind] ?? 0;
    if (value === undefined || value <= 0 || rate === 0) return ceiling;
    seconds = (policy.max_expected_loss.amount / (value * rate)) * 3600;
  }
  if (!Number.isFinite(seconds) || seconds < 0) return seconds === Infinity ? ceiling : 0;
  // The epsilon keeps binary rounding (1 / (10000 × 1e-4) × 3600 = 3599.999…) from costing a whole second.
  return Math.min(ceiling, Math.floor(seconds + 1e-6));
}

export interface FreshnessCheck {
  rule: "freshness";
  kind: EvidenceKind;
  ok: boolean;
  detail: string;
  age_seconds: number | null;
  max_age_seconds: number;
}

export interface FreshnessVerdict {
  ok: boolean;
  checks: FreshnessCheck[];
  /** Kinds for which fresher (or any) evidence would change the answer: fetch it, or ask the agent for it. */
  refresh: EvidenceKind[];
  /** The policy and clock actually applied, to keep with the verdict as proof of the risk accepted. */
  applied: {
    now: string;
    action: string | null;
    amount: number | null;
    /** The amount, or the risk value assigned to the action; null when there was neither (ceiling applied). */
    value_at_risk: number | null;
    currency: string;
    max_expected_loss: { amount: number; currency: string };
    revocation_rate_per_hour: Partial<Record<EvidenceKind, number>>;
    max_age_seconds: number;
    max_clock_skew_seconds: number;
    custom_max_age: boolean;
  };
}

function human(seconds: number): string {
  if (seconds < 120) return `${seconds} s`;
  if (seconds < 7200) return `${Math.floor(seconds / 60)} min`;
  if (seconds < 172_800) return `${Math.floor(seconds / 3600)} h`;
  return `${Math.floor(seconds / 86_400)} d`;
}

/**
 * Checks that, for every kind the policy requires, the freshest evidence given says "in force", is not
 * past its own validity, is not dated in the future beyond the clock skew, and is younger than the maximum
 * age for this amount. Fails closed: missing, malformed or foreign-currency input never passes.
 */
export function checkFreshness(policy: FreshnessPolicy, evidence: StatusEvidence[], q: { action?: string; amount?: number; currency?: string; now?: Date } = {}): FreshnessVerdict {
  const now = q.now ?? new Date();
  const nowMs = now.getTime();
  const currency = policy.max_expected_loss.currency;
  const qCurrency = q.currency?.trim().toUpperCase();
  const amount = q.amount;
  const action = q.action?.trim().toLowerCase() || undefined;
  const amountValid = amount === undefined || (typeof amount === "number" && Number.isFinite(amount) && amount >= 0);
  const value = amountValid ? valueAtRisk(policy, amount, action) : undefined;
  const applied: FreshnessVerdict["applied"] = {
    now: Number.isNaN(nowMs) ? "invalid" : now.toISOString(),
    action: action ?? null,
    amount: amount ?? null,
    value_at_risk: value ?? null,
    currency,
    max_expected_loss: policy.max_expected_loss,
    revocation_rate_per_hour: policy.revocation_rate_per_hour,
    max_age_seconds: policy.max_age_seconds,
    max_clock_skew_seconds: policy.max_clock_skew_seconds,
    custom_max_age: !!policy.max_age
  };
  const checks: FreshnessCheck[] = [];
  const refresh: EvidenceKind[] = [];

  if (Number.isNaN(nowMs)) {
    for (const kind of policy.require) checks.push({ rule: "freshness", kind, ok: false, detail: "the verifier's clock is not a valid date", age_seconds: null, max_age_seconds: 0 });
    return { ok: false, checks, refresh, applied };
  }
  if (!amountValid || (qCurrency && qCurrency !== currency)) {
    const detail = !amountValid ? "amount is not a finite number >= 0" : `loss tolerance is in ${currency}, operation in ${qCurrency}`;
    for (const kind of policy.require) checks.push({ rule: "freshness", kind, ok: false, detail, age_seconds: null, max_age_seconds: 0 });
    return { ok: false, checks, refresh, applied };
  }

  for (const kind of policy.require) {
    const max = maxStatusAgeSeconds(policy, kind, amount, action);
    const what = amount !== undefined ? `for ${amount} ${currency}` : value !== undefined ? `for "${action}" (risk value ${value} ${currency})` : `no amount${action ? ` and no risk value for "${action}"` : ""}, ceiling applies`;
    const limit = `${what}: at most ${human(max)}`;
    const usable = evidence.filter((e) => e && e.kind === kind && !Number.isNaN(Date.parse(e.as_of)));
    if (!usable.length) {
      checks.push({ rule: "freshness", kind, ok: false, detail: `no ${kind} status evidence; ${limit}`, age_seconds: null, max_age_seconds: max });
      refresh.push(kind);
      continue;
    }
    // Freshest first: a newer statement supersedes an older one, whatever it says.
    let e = usable[0]!;
    let asOf = Date.parse(e.as_of);
    for (const candidate of usable) {
      const t = Date.parse(candidate.as_of);
      if (t > asOf) {
        e = candidate;
        asOf = t;
      }
    }
    const age = Math.floor((nowMs - asOf) / 1000);
    const from = e.source ? ` (${e.source})` : "";
    if (asOf - nowMs > policy.max_clock_skew_seconds * 1000) {
      checks.push({ rule: "freshness", kind, ok: false, detail: `${kind} evidence${from} is dated ${e.as_of}, after the verifier's clock ${applied.now} beyond the ${policy.max_clock_skew_seconds} s tolerance`, age_seconds: age, max_age_seconds: max });
      continue;
    }
    if (e.valid_until && !Number.isNaN(Date.parse(e.valid_until)) && Date.parse(e.valid_until) < nowMs) {
      checks.push({ rule: "freshness", kind, ok: false, detail: `${kind} evidence${from} expired at ${e.valid_until}`, age_seconds: Math.max(0, age), max_age_seconds: max });
      refresh.push(kind);
      continue;
    }
    if (!e.in_force) {
      checks.push({ rule: "freshness", kind, ok: false, detail: `${kind} is not in force${e.status ? ` (${e.status})` : ""} as of ${e.as_of}${from}`, age_seconds: Math.max(0, age), max_age_seconds: max });
      continue;
    }
    const ageShown = Math.max(0, age);
    const fresh = ageShown <= max;
    checks.push({ rule: "freshness", kind, ok: fresh, detail: `${kind} status${from} is ${human(ageShown)} old; ${limit}`, age_seconds: ageShown, max_age_seconds: max });
    if (!fresh) refresh.push(kind);
  }
  return { ok: checks.length > 0 && checks.every((c) => c.ok), checks, refresh, applied };
}

/**
 * The mandate (checkAction) and the freshness of the status, in one answer: allowed only when both pass.
 * The freshness check uses the action's name, amount and currency and the same clock.
 */
export function checkFreshAction(mandate: Mandate, q: ActionQuery, p: { policy: FreshnessPolicy; evidence: StatusEvidence[] }): { allowed: boolean; mandate: ActionVerdict; freshness: FreshnessVerdict } {
  const now = q.now ?? new Date();
  const m = checkAction(mandate, { ...q, now });
  const f = checkFreshness(p.policy, p.evidence, { action: q.action, amount: q.amount, currency: q.currency, now });
  return { allowed: m.allowed && f.ok, mandate: m, freshness: f };
}

/** Evidence about the certificate from a CRL lookup (checkRevocation / verifyCrl().lookup). */
export function evidenceFromRevocation(r: RevocationStatus, source?: string): StatusEvidence {
  return {
    kind: "certificate",
    in_force: !r.revoked,
    as_of: r.crl_this_update,
    valid_until: r.crl_next_update,
    source: source ?? "CRL",
    status: r.revoked ? (r.reason ?? "revoked") : "not revoked"
  };
}

/**
 * Evidence about the credential from an answer the issuer signed (a verdict from /allowed, a paid
 * verification receipt): any answer carrying `credential_id`, `status` and an Ed25519 `attestation`. The
 * agent can staple such an answer to its request so the verifier needs no network. The answer must be
 * about `credentialId` and verify with the issuer's key; the status instant is the signature's.
 */
export async function evidenceFromSignedStatus(answer: Record<string, unknown>, issuerPublicJwk: JsonWebKey, credentialId: string): Promise<StatusEvidence> {
  if (!answer || typeof answer !== "object") throw new KyaError("INVALID_INPUT", "signed status: expected an object");
  if (answer.credential_id !== credentialId) throw new KyaError("INVALID_INPUT", `signed status is about ${String(answer.credential_id)}, not ${credentialId}`);
  if (typeof answer.status !== "string") throw new KyaError("INVALID_INPUT", "signed status has no status");
  const sig = await verifyAttestation(answer, issuerPublicJwk);
  if (!sig.valid || !sig.signed_at) throw new KyaError("INVALID_INPUT", `signed status does not verify: ${sig.reason ?? "no signature time"}`);
  return { kind: "credential", in_force: answer.status === "active", as_of: sig.signed_at, source: "issuer signed status", status: answer.status };
}
