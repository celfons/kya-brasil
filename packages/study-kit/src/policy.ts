/**
 * Task T2, "policy quality": the mandate the participant issued in T1, graded against the scenario's answer key.
 *
 * Scenario: the company lets an AI agent buy office supplies from supplier X, up to R$ 500 per purchase and
 * R$ 1,500 per day, for 30 days, without delegating. The answer key below is that sentence as a mandate. Every
 * field that deviates is recorded with its direction: "permissive" (the agent can do more than the scenario
 * allows), "restrictive" (less: legitimate purchases would be refused) or "neutral" (not in the scenario).
 */
import { normalizeCounterparty } from "@kya-brasil/core";

export const SCENARIO = {
  action: "buy",
  currency: "BRL",
  maxPerOperation: 500,
  maxPerDay: 1500,
  /** Supplier X ("Papelaria Exemplo Ltda", fake): the only counterparty. */
  supplierCnpj: "98765432000198",
  /** Another supplier, never authorized (used by T3's "wrong counterparty" case). */
  otherSupplierCnpj: "55566677000183",
  validityDays: 30,
  /** Accepted slack on the 30 days (clock, time zones, "end of day"): 29 to 31 days. */
  validityToleranceDays: 1
} as const;

export type PolicyGrade = "correct" | "permissive" | "restrictive" | "invalid";
export type Direction = "permissive" | "restrictive" | "neutral";

export interface Deviation {
  field: string;
  direction: Direction;
  detail: string;
}

export interface PolicyResult {
  grade: PolicyGrade;
  deviations: Deviation[];
}

const DAY = 86_400_000;

/**
 * Grades a credential's mandate. `credential` is the T1 output (or null when T1 produced nothing verifiable, which
 * grades "invalid"). Permissive deviations win over restrictive ones: the security-relevant mistake is reported.
 */
export function gradePolicy(credential: { mandate?: Record<string, unknown>; issued_at?: string; expires_at?: string } | null, verified: boolean): PolicyResult {
  if (!credential || !credential.mandate || typeof credential.mandate !== "object" || !verified) {
    return { grade: "invalid", deviations: [{ field: "credential", direction: "neutral", detail: "no verifiable credential (T1 must pass first)" }] };
  }
  const m = credential.mandate;
  const d: Deviation[] = [];
  const add = (field: string, direction: Direction, detail: string) => d.push({ field, direction, detail });

  // actions: exactly ["buy"]. Absent or [] means any action.
  const actions = Array.isArray(m.actions) ? (m.actions as string[]).map((a) => String(a).toLowerCase()) : null;
  if (!actions || actions.length === 0) add("actions", "permissive", "any action allowed (no action list)");
  else {
    const extra = actions.filter((a) => a !== SCENARIO.action);
    if (extra.length) add("actions", "permissive", `extra actions: ${extra.join(", ")}`);
    if (!actions.includes(SCENARIO.action)) add("actions", "restrictive", `"${SCENARIO.action}" is not allowed`);
  }

  money("max_per_operation", SCENARIO.maxPerOperation);
  money("max_per_day", SCENARIO.maxPerDay);
  function money(field: "max_per_operation" | "max_per_day", expected: number) {
    const v = m[field] as { amount?: unknown; currency?: unknown } | undefined;
    if (!v || typeof v !== "object") return add(field, "permissive", "no ceiling");
    if (v.currency !== SCENARIO.currency) return add(field, "restrictive", `ceiling in ${String(v.currency)}, purchases are in ${SCENARIO.currency}`);
    const amount = Number(v.amount);
    if (amount > expected) add(field, "permissive", `${amount} > ${expected} ${SCENARIO.currency}`);
    else if (amount < expected) add(field, "restrictive", `${amount} < ${expected} ${SCENARIO.currency}`);
  }

  const currencies = Array.isArray(m.currencies) ? (m.currencies as string[]).map((c) => String(c).toUpperCase()) : null;
  if (!currencies || currencies.length === 0) add("currencies", "permissive", "any currency");
  else {
    const extra = currencies.filter((c) => c !== SCENARIO.currency);
    if (extra.length) add("currencies", "permissive", `extra currencies: ${extra.join(", ")}`);
    if (!currencies.includes(SCENARIO.currency)) add("currencies", "restrictive", `${SCENARIO.currency} not allowed`);
  }

  const cps = Array.isArray(m.counterparties) ? (m.counterparties as string[]).map((c) => normalizeCounterparty(String(c))) : null;
  if (!cps || cps.length === 0) add("counterparties", "permissive", "no counterparty restriction (any supplier)");
  else {
    const extra = cps.filter((c) => c !== SCENARIO.supplierCnpj);
    if (extra.length) add("counterparties", "permissive", `${extra.length} counterparty entr${extra.length === 1 ? "y" : "ies"} besides supplier X`);
    if (!cps.includes(SCENARIO.supplierCnpj)) add("counterparties", "restrictive", "supplier X is not listed");
  }

  if (Array.isArray(m.payment_instruments) && m.payment_instruments.length) add("payment_instruments", "neutral", `${m.payment_instruments.length} payment instrument(s) listed (not in the scenario)`);

  if (m.delegation !== undefined && m.delegation !== null) add("delegation", "permissive", "delegation allowed");

  // Validity: from issuance (or valid_from, when later) to the earliest of valid_until and the credential's expiry.
  const issued = Date.parse(credential.issued_at ?? "");
  const from = Math.max(issued, Date.parse(String(m.valid_from ?? "")) || issued);
  const untilCandidates = [Date.parse(String(m.valid_until ?? "")), Date.parse(credential.expires_at ?? "")].filter(Number.isFinite);
  if (!Number.isFinite(issued) || !untilCandidates.length) add("valid_until", "permissive", "no end of validity");
  else {
    const days = (Math.min(...untilCandidates) - from) / DAY;
    const shown = days.toFixed(1);
    if (days > SCENARIO.validityDays + SCENARIO.validityToleranceDays) add("valid_until", "permissive", `in force for ${shown} days (> ${SCENARIO.validityDays})`);
    else if (days < SCENARIO.validityDays - SCENARIO.validityToleranceDays) add("valid_until", "restrictive", `in force for ${shown} days (< ${SCENARIO.validityDays})`);
    const startsIn = (from - issued) / DAY;
    if (startsIn > SCENARIO.validityToleranceDays) add("valid_from", "restrictive", `starts ${startsIn.toFixed(1)} days after issuance`);
  }

  const known = new Set(["actions", "max_per_operation", "max_per_day", "currencies", "counterparties", "payment_instruments", "valid_from", "valid_until", "delegation"]);
  const extensions = Object.keys(m).filter((k) => !known.has(k));
  if (extensions.length) add("extensions", "neutral", `extension fields (not evaluated): ${extensions.join(", ")}`);

  const grade: PolicyGrade = d.some((x) => x.direction === "permissive") ? "permissive" : d.some((x) => x.direction === "restrictive") ? "restrictive" : "correct";
  return { grade, deviations: d };
}

/** The answer key as a mandate (used to build the kit's own reference credential for T3 and T4). */
export function referenceMandate(now: Date) {
  return {
    actions: [SCENARIO.action],
    max_per_operation: { amount: SCENARIO.maxPerOperation, currency: SCENARIO.currency },
    max_per_day: { amount: SCENARIO.maxPerDay, currency: SCENARIO.currency },
    currencies: [SCENARIO.currency],
    counterparties: [SCENARIO.supplierCnpj],
    payment_instruments: [],
    valid_from: now.toISOString(),
    valid_until: new Date(now.getTime() + SCENARIO.validityDays * DAY).toISOString(),
    delegation: null
  };
}
