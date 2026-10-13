/**
 * Acts: what an agent did, written next to what it was allowed to do. The party that accepted the
 * action (usually the counterparty) registers it; the issuer checks it against the mandate, adds the
 * amounts already registered today, signs a receipt and keeps only the metadata and an optional hash.
 *
 * The act text below is what the agent MAY sign to show it intended the action; the signature is
 * optional and, when present and valid, the receipt says `agent_signed: true`.
 */
import { KyaError, type AgentKey } from "./types";
import { normalizeCounterparty } from "./mandate";

export interface ActInput {
  action: string;
  amount?: number;
  currency?: string;
  counterparty?: string;
  /** Free reference for the registrant (order number, invoice, URL), up to 200 chars. */
  reference?: string;
  /** SHA-256 hex of the document the act refers to (order, contract). Only the hash is stored. */
  content_sha256?: string;
  /** Who registers: the counterparty that accepted the action (default) or the agent itself. */
  registered_by?: "counterparty" | "agent";
  /** Identifier of the registrant (CNPJ, domain or address), up to 128 chars. */
  registrant?: string;
  /** The agent's signature over actText(...), optional (EIP-191 hex or Ed25519 base64url). */
  agent_signature?: string;
}

export interface Act extends ActInput {
  action: string;
  amount?: number;
  currency?: string;
  counterparty?: string;
}

export function validateAct(input: Record<string, unknown>): Act {
  const bad = (f: string, what: string) => new KyaError("INVALID_INPUT", `act.${f} must be ${what}`);
  if (typeof input.action !== "string" || !/^[a-z][a-z0-9_-]{1,31}$/.test(input.action)) throw bad("action", "a lowercase word like pay, order, sign");
  const act: Act = { action: input.action };
  if (input.amount !== undefined && input.amount !== null && input.amount !== "") {
    const n = typeof input.amount === "string" ? Number(input.amount) : input.amount;
    if (typeof n !== "number" || !Number.isFinite(n) || n < 0) throw bad("amount", "a non-negative number");
    act.amount = n;
  }
  if (input.currency !== undefined && input.currency !== null && input.currency !== "") {
    if (typeof input.currency !== "string" || !/^[A-Za-z0-9]{2,10}$/.test(input.currency)) throw bad("currency", "a code like BRL or USDC");
    act.currency = input.currency.toUpperCase();
  }
  if (act.amount !== undefined && !act.currency) throw bad("currency", "given when amount is given");
  if (input.counterparty !== undefined && input.counterparty !== null && input.counterparty !== "") {
    if (typeof input.counterparty !== "string" || input.counterparty.length > 128) throw bad("counterparty", "a CNPJ, domain or address up to 128 chars");
    act.counterparty = normalizeCounterparty(input.counterparty);
  }
  if (input.reference !== undefined && input.reference !== null && input.reference !== "") {
    if (typeof input.reference !== "string" || input.reference.length > 200) throw bad("reference", "a string up to 200 chars");
    act.reference = input.reference;
  }
  if (input.content_sha256 !== undefined && input.content_sha256 !== null && input.content_sha256 !== "") {
    if (typeof input.content_sha256 !== "string" || !/^[0-9a-fA-F]{64}$/.test(input.content_sha256)) throw bad("content_sha256", "64 hex characters");
    act.content_sha256 = input.content_sha256.toLowerCase();
  }
  if (input.registered_by !== undefined) {
    if (input.registered_by !== "counterparty" && input.registered_by !== "agent") throw bad("registered_by", "counterparty or agent");
    act.registered_by = input.registered_by;
  }
  if (input.registrant !== undefined && input.registrant !== null && input.registrant !== "") {
    if (typeof input.registrant !== "string" || input.registrant.length > 128) throw bad("registrant", "a string up to 128 chars");
    act.registrant = normalizeCounterparty(input.registrant);
  }
  if (input.agent_signature !== undefined && input.agent_signature !== null && input.agent_signature !== "") {
    if (typeof input.agent_signature !== "string" || input.agent_signature.length > 400) throw bad("agent_signature", "a signature string");
    act.agent_signature = input.agent_signature;
  }
  return act;
}

/** The text the agent signs to show it intended the act. Line-based; empty fields are written as "-". */
export function actText(p: { issuer: string; credential_id: string; agent: AgentKey; act: Act }): string {
  const a = p.act;
  return [
    "KYA Brasil: act",
    `issuer: ${p.issuer}`,
    `credential: ${p.credential_id}`,
    `agent: ${p.agent.kind}:${p.agent.id}`,
    `action: ${a.action}`,
    `amount: ${a.amount !== undefined ? `${a.amount} ${a.currency}` : "-"}`,
    `counterparty: ${a.counterparty ?? "-"}`,
    `reference: ${a.reference ?? "-"}`,
    `content_sha256: ${a.content_sha256 ?? "-"}`
  ].join("\n");
}

/** UTC calendar day of a timestamp, the unit of max_per_day. */
export function dayOf(ts: Date | string): string {
  return new Date(ts).toISOString().slice(0, 10);
}

/** Sum of the amounts registered today in the mandate's daily currency (other currencies are not converted). */
export function spentToday(acts: { amount: number | null; currency: string | null; allowed: boolean }[], currency: string): number {
  return acts.filter((a) => a.allowed && a.currency === currency && typeof a.amount === "number").reduce((s, a) => s + (a.amount as number), 0);
}
