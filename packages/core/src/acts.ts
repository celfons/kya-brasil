/**
 * Acts: what an agent did, written next to what it was allowed to do. The party that accepted the
 * action (usually the counterparty) registers it; the issuer checks it against the mandate, adds the
 * amounts already registered today, signs a receipt and keeps only the metadata and an optional hash.
 *
 * The act text below is what the agent MAY sign to show it intended the action; the signature is
 * optional and, when present and valid, the receipt says `agent_signed: true`.
 *
 * D-18: only acts with a proof of origin count toward the daily total. The proof is the agent's signature
 * over the act text, or the agent's own signed KYA request that the counterparty received (`agent_request`).
 * Acts without a proof are kept as evidence, signed, with `counted: false`.
 */
import { KyaError, type AgentKey } from "./types";
import { normalizeCounterparty } from "./mandate";
import { type AgentRequestProof, requestText } from "./request";
import { verifyAgentSignature } from "./challenge";

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
  /** D-18: the agent's signed KYA request that led to the act, as the counterparty received it. */
  agent_request?: AgentRequestProof;
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
  if (input.agent_request !== undefined && input.agent_request !== null) act.agent_request = validateAgentRequest(input.agent_request, bad);
  return act;
}

function validateAgentRequest(input: unknown, bad: (f: string, what: string) => KyaError): AgentRequestProof {
  if (typeof input !== "object" || Array.isArray(input)) throw bad("agent_request", "an object with method, url, created, expires, signature and optional content_sha256");
  const r = input as Record<string, unknown>;
  if (typeof r.method !== "string" || !/^[A-Za-z]{1,10}$/.test(r.method)) throw bad("agent_request.method", "an HTTP method");
  if (typeof r.url !== "string" || r.url.length > 2048 || !URL.canParse(r.url) || !/^https?:$/.test(new URL(r.url).protocol)) throw bad("agent_request.url", "an http(s) URL up to 2048 chars");
  if (!Number.isInteger(r.created) || !Number.isInteger(r.expires)) throw bad("agent_request.created/expires", "Unix seconds (KYA-Created, KYA-Expires)");
  if (typeof r.signature !== "string" || !r.signature || r.signature.length > 400) throw bad("agent_request.signature", "the KYA-Signature header");
  const proof: AgentRequestProof = { method: r.method.toUpperCase(), url: r.url, created: r.created as number, expires: r.expires as number, signature: r.signature };
  if (r.content_sha256 !== undefined && r.content_sha256 !== null && r.content_sha256 !== "") {
    if (typeof r.content_sha256 !== "string" || !/^[0-9a-fA-F]{64}$/.test(r.content_sha256)) throw bad("agent_request.content_sha256", "64 hex characters (KYA-Content-SHA256)");
    proof.content_sha256 = r.content_sha256.toLowerCase();
  }
  return proof;
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

/** D-18: an agent request is accepted as the proof of an act up to a day after it was signed. */
export const ACT_PROOF_MAX_AGE_S = 86_400;
const ACT_PROOF_MAX_SKEW_S = 300;
const ACT_PROOF_MAX_TTL_S = 600;

export interface ActProof {
  proof: "agent_signature" | "agent_request" | "none";
  agent_signed: boolean;
  /** The signature that proves the act; its hash keeps one proof to one act. */
  proof_signature: string | null;
}

/**
 * The proof of origin of an act (D-18): the agent's signature over the act text, or the agent's signed KYA
 * request that the counterparty received (SPEC section 14). An invalid proof throws; a missing one returns
 * "none" (the act is kept as evidence and does not count toward the daily total).
 */
export async function checkActProof(p: { issuer: string; credential_id: string; agent: AgentKey; act: Act; now?: Date }): Promise<ActProof> {
  const { act } = p;
  let agent_signed = false;
  if (act.agent_signature) {
    agent_signed = await verifyAgentSignature(p.agent, actText({ issuer: p.issuer, credential_id: p.credential_id, agent: p.agent, act }), act.agent_signature);
    if (!agent_signed) throw new KyaError("CHALLENGE_FAILED", "agent_signature does not match the agent key over the act text (GET /v1/acts/text for the exact lines)");
  }
  const r = act.agent_request;
  if (r) {
    const nowS = Math.floor((p.now ?? new Date()).getTime() / 1000);
    if (r.created > nowS + ACT_PROOF_MAX_SKEW_S) throw new KyaError("INVALID_INPUT", "agent_request.created is in the future");
    if (nowS - r.created > ACT_PROOF_MAX_AGE_S) throw new KyaError("INVALID_INPUT", "agent_request is older than 24 hours; register acts when they happen");
    if (r.expires < r.created || r.expires - r.created > ACT_PROOF_MAX_TTL_S) throw new KyaError("INVALID_INPUT", `agent_request lifetime must be between 0 and ${ACT_PROOF_MAX_TTL_S}s`);
    if (act.content_sha256 && r.content_sha256 && act.content_sha256 !== r.content_sha256) throw new KyaError("INVALID_INPUT", "act.content_sha256 differs from the body hash the agent signed (agent_request.content_sha256)");
    const text = requestText({ credentialId: p.credential_id, method: r.method, url: r.url, created: r.created, expires: r.expires, contentSha256: r.content_sha256 ?? null });
    if (!(await verifyAgentSignature(p.agent, text, r.signature))) throw new KyaError("CHALLENGE_FAILED", "agent_request.signature does not match the agent key over the request text (SPEC section 14)");
  }
  let proof: ActProof["proof"] = "none";
  if (act.agent_signature) proof = "agent_signature";
  else if (r) proof = "agent_request";
  return { proof, agent_signed, proof_signature: act.agent_signature ?? r?.signature ?? null };
}

/** UTC calendar day of a timestamp, the unit of max_per_day. */
export function dayOf(ts: Date | string): string {
  return new Date(ts).toISOString().slice(0, 10);
}

/**
 * Sum of the amounts registered today in the mandate's daily currency (other currencies are not converted).
 * Only allowed acts that count (D-18: they carry a proof of origin) are added; `counted` defaults to true.
 */
export function spentToday(acts: { amount: number | null; currency: string | null; allowed: boolean; counted?: boolean }[], currency: string): number {
  return acts.filter((a) => a.allowed && (a.counted ?? true) && a.currency === currency && typeof a.amount === "number").reduce((s, a) => s + (a.amount as number), 0);
}
