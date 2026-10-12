/**
 * Mandate: what the company lets the agent do. Free JSON validated against a public schema
 * (/.well-known/kya-mandate.schema.json). The reserved fields below are evaluated by
 * `checkAction`; extensions are carried in the credential untouched and never evaluated.
 * Validation is hand-written (no Ajv: `new Function` is blocked on Workers).
 */
import { type Mandate, type MandateCore, KyaError } from "./types";

export const MANDATE_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://kya.example/.well-known/kya-mandate.schema.json",
  title: "KYA Brasil agent mandate",
  description: "What a company authorizes an AI agent to do on its behalf. Reserved fields are evaluated by check_action; any other field is carried in the credential as an extension and not evaluated.",
  type: "object",
  properties: {
    actions: { type: "array", items: { type: "string", pattern: "^[a-z][a-z0-9_-]{1,31}$" }, maxItems: 32, description: "Permitted actions (lowercase vocabulary, e.g. buy, sell, quote, pay, sign)." },
    max_per_operation: { $ref: "#/$defs/money", description: "Ceiling per single operation." },
    max_per_day: { $ref: "#/$defs/money", description: "Ceiling per calendar day (UTC)." },
    currencies: { type: "array", items: { type: "string", pattern: "^[A-Z0-9]{2,10}$" }, maxItems: 16 },
    counterparties: { type: "array", items: { type: "string", maxLength: 128 }, maxItems: 200, description: "CNPJs, domains or wallet addresses; empty or absent = any." },
    valid_from: { type: "string", format: "date-time" },
    valid_until: { type: "string", format: "date-time" }
  },
  additionalProperties: true,
  $defs: { money: { type: "object", properties: { amount: { type: "number", exclusiveMinimum: 0 }, currency: { type: "string", pattern: "^[A-Z0-9]{2,10}$" } }, required: ["amount", "currency"], additionalProperties: false } }
} as const;

const MAX_MANDATE_BYTES = 8192;
const isMoney = (v: unknown): v is { amount: number; currency: string } =>
  !!v && typeof v === "object" && typeof (v as { amount?: unknown }).amount === "number" && (v as { amount: number }).amount > 0 && Number.isFinite((v as { amount: number }).amount) && typeof (v as { currency?: unknown }).currency === "string" && /^[A-Z0-9]{2,10}$/.test((v as { currency: string }).currency) && Object.keys(v as object).length === 2;
const isoDate = (s: unknown) => typeof s === "string" && !Number.isNaN(Date.parse(s));

/** Throws KyaError INVALID_INPUT with the first problem found; returns the mandate with reserved fields normalized. */
export function validateMandate(input: unknown): Mandate {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new KyaError("INVALID_INPUT", "mandate must be a JSON object");
  if (JSON.stringify(input).length > MAX_MANDATE_BYTES) throw new KyaError("INVALID_INPUT", `mandate larger than ${MAX_MANDATE_BYTES} bytes`);
  const m = { ...(input as Record<string, unknown>) };
  const bad = (field: string, why: string) => new KyaError("INVALID_INPUT", `mandate.${field}: ${why}`);
  if (m.actions !== undefined) {
    if (!Array.isArray(m.actions) || m.actions.length > 32 || !m.actions.every((a) => typeof a === "string" && /^[a-z][a-z0-9_-]{1,31}$/.test(a))) throw bad("actions", "array of up to 32 lowercase identifiers");
    m.actions = [...new Set(m.actions as string[])];
  }
  for (const k of ["max_per_operation", "max_per_day"] as const) if (m[k] !== undefined && !isMoney(m[k])) throw bad(k, "{ amount > 0, currency }");
  if (m.currencies !== undefined) {
    if (!Array.isArray(m.currencies) || m.currencies.length > 16 || !m.currencies.every((c) => typeof c === "string" && /^[A-Z0-9]{2,10}$/.test(c))) throw bad("currencies", "array of up to 16 upper-case codes");
  }
  if (m.counterparties !== undefined) {
    if (!Array.isArray(m.counterparties) || m.counterparties.length > 200 || !m.counterparties.every((c) => typeof c === "string" && c.length > 0 && c.length <= 128)) throw bad("counterparties", "array of up to 200 strings");
    m.counterparties = (m.counterparties as string[]).map(normalizeCounterparty);
  }
  for (const k of ["valid_from", "valid_until"] as const) if (m[k] !== undefined && !isoDate(m[k])) throw bad(k, "ISO 8601 date-time");
  if (m.valid_from && m.valid_until && Date.parse(m.valid_from as string) >= Date.parse(m.valid_until as string)) throw bad("valid_until", "must be after valid_from");
  return m as Mandate;
}

export function normalizeCounterparty(c: string): string {
  const s = c.trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(s)) return s.toLowerCase();
  const digits = s.replace(/[^0-9A-Za-z]/g, "");
  if (digits.length === 14 && /^[0-9A-Z]{12}[0-9]{2}$/i.test(digits)) return digits.toUpperCase();
  return s.toLowerCase();
}

export interface ActionQuery {
  action?: string;
  amount?: number;
  currency?: string;
  counterparty?: string;
  /** Amount already spent today (UTC) by this agent, if the verifier tracks it; the issuer does not. */
  spent_today?: number;
  now?: Date;
}

export interface ActionVerdict {
  allowed: boolean;
  /** Every reserved rule that was evaluated, with its result. */
  checks: { rule: keyof MandateCore; ok: boolean; detail: string }[];
  /** Fields of the mandate that exist but are not evaluated by this service. */
  not_evaluated: string[];
}

const RESERVED: (keyof MandateCore)[] = ["actions", "max_per_operation", "max_per_day", "currencies", "counterparties", "valid_from", "valid_until"];

/** Deterministic evaluation of the reserved mandate fields against an intended action. */
export function checkAction(mandate: Mandate, q: ActionQuery): ActionVerdict {
  const now = q.now ?? new Date();
  const checks: ActionVerdict["checks"] = [];
  const push = (rule: keyof MandateCore, ok: boolean, detail: string) => checks.push({ rule, ok, detail });
  if (mandate.valid_from) push("valid_from", now.getTime() >= Date.parse(mandate.valid_from), `mandate starts ${mandate.valid_from}`);
  if (mandate.valid_until) push("valid_until", now.getTime() <= Date.parse(mandate.valid_until), `mandate ends ${mandate.valid_until}`);
  if (mandate.actions) {
    const a = (q.action ?? "").toLowerCase();
    push("actions", !!a && mandate.actions.includes(a), a ? `action "${a}" ${mandate.actions.includes(a) ? "is" : "is not"} in [${mandate.actions.join(", ")}]` : "no action given; mandate restricts actions");
  }
  if (mandate.currencies && q.currency) push("currencies", mandate.currencies.includes(q.currency.toUpperCase()), `currency ${q.currency.toUpperCase()} ${mandate.currencies.includes(q.currency.toUpperCase()) ? "allowed" : "not in"} [${mandate.currencies.join(", ")}]`);
  if (mandate.max_per_operation && q.amount !== undefined) {
    const sameCurrency = !q.currency || q.currency.toUpperCase() === mandate.max_per_operation.currency;
    push("max_per_operation", sameCurrency && q.amount <= mandate.max_per_operation.amount, sameCurrency ? `${q.amount} vs ceiling ${mandate.max_per_operation.amount} ${mandate.max_per_operation.currency}` : `ceiling is in ${mandate.max_per_operation.currency}, operation in ${q.currency}`);
  }
  if (mandate.max_per_day && q.amount !== undefined) {
    const total = q.amount + (q.spent_today ?? 0);
    const sameCurrency = !q.currency || q.currency.toUpperCase() === mandate.max_per_day.currency;
    push("max_per_day", sameCurrency && total <= mandate.max_per_day.amount, sameCurrency ? `${total} today (incl. this one) vs ceiling ${mandate.max_per_day.amount} ${mandate.max_per_day.currency}` : `ceiling is in ${mandate.max_per_day.currency}, operation in ${q.currency}`);
  }
  if (mandate.counterparties && mandate.counterparties.length && q.counterparty) {
    const c = normalizeCounterparty(q.counterparty);
    push("counterparties", mandate.counterparties.includes(c), `${c} ${mandate.counterparties.includes(c) ? "is" : "is not"} an allowed counterparty`);
  }
  const not_evaluated = Object.keys(mandate).filter((k) => !RESERVED.includes(k as keyof MandateCore));
  return { allowed: checks.every((c) => c.ok), checks, not_evaluated };
}
