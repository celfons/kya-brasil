/**
 * Delegation to sub-agents (D-30, docs/SPEC.md section 17).
 *
 * The principal allows it once, in the mandate it signs with its certificate (`delegation: { max_depth,
 * max_ttl_seconds }`). The credential's agent then signs, with its own key, a short-lived delegation that hands a
 * NARROWER mandate to another key; that key may delegate again while the depth allows. Nothing is stored by the
 * issuer: the chain travels with the request (`KYA-Delegation`) and any verifier checks it offline against the
 * credential. An action is allowed only when every mandate in the chain allows it.
 *
 * Delegation text (what the delegator signs; EIP-191 for evm/erc8004, raw Ed25519 for web-bot-auth):
 *   KYA Brasil: delegation
 *   credential: <credential_id>
 *   parent: <signature_sha256 of the previous delegation | ->
 *   delegate: <kind>:<id>
 *   depth: <1..3>
 *   issued: <ISO 8601>
 *   expires: <ISO 8601>
 *   mandate-sha256: <hex SHA-256 of the canonical JSON of the delegated mandate>
 */
import { canonicalize } from "./attestation.js";
import { normalizeAgentKey, verifyAgentSignature } from "./challenge.js";
import { type ActionQuery, type ActionVerdict, DELEGATION_MAX_DEPTH, DELEGATION_MIN_TTL_SECONDS, checkAction, counterpartyMatches, normalizeCounterparty, validateMandate } from "./mandate.js";
import { type AgentKey, type Mandate, KyaError } from "./types.js";

/** A delegated mandate travels in a header on every request: keep it small. */
export const DELEGATED_MANDATE_MAX_BYTES = 2048;
/** Clock difference tolerated on `issued_at`. */
const SKEW_MS = 300_000;

export interface Delegation {
  version: 1;
  credential_id: string;
  /** `signature_sha256` of the delegation this one extends; null at depth 1 (signed by the credential's agent). */
  parent: string | null;
  /** The key that receives the mandate (evm or web-bot-auth). */
  delegate: AgentKey;
  depth: number;
  issued_at: string;
  expires_at: string;
  mandate: Mandate;
  /** Signature by the delegator: the credential's agent at depth 1, the previous delegate after that. */
  signature: string;
}

/** The credential fields a chain is checked against (a Credential, or the `credential` of a verification). */
export interface DelegationAnchor {
  credential_id: string;
  agent: AgentKey;
  mandate: Mandate;
  expires_at: string;
}

const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256Hex = async (text: string) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));

/**
 * Why `child` is not contained in `parent` (empty array = contained). Every reserved field the parent restricts
 * must be at least as restricted in the child; a child may restrict what the parent leaves open. Extensions
 * (non-reserved fields) are not compared: they are never evaluated.
 */
export function mandateSubsetProblems(parent: Mandate, child: Mandate): string[] {
  const p: string[] = [];
  if (parent.actions) {
    if (!child.actions) p.push("actions: parent restricts actions, delegated mandate must list them");
    else for (const a of child.actions) if (!parent.actions.includes(a)) p.push(`actions: "${a}" is not in the parent mandate`);
  }
  for (const k of ["max_per_operation", "max_per_day"] as const) {
    const pm = parent[k];
    const cm = child[k];
    if (!pm) continue;
    if (!cm) p.push(`${k}: parent sets a ceiling, delegated mandate must too`);
    else if (cm.currency !== pm.currency) p.push(`${k}: currency ${cm.currency} differs from the parent's ${pm.currency}`);
    else if (cm.amount > pm.amount) p.push(`${k}: ${cm.amount} is above the parent's ${pm.amount}`);
  }
  if (parent.currencies) {
    if (!child.currencies) p.push("currencies: parent restricts currencies, delegated mandate must list them");
    else for (const c of child.currencies) if (!parent.currencies.includes(c)) p.push(`currencies: ${c} is not in the parent mandate`);
  }
  if (parent.counterparties && parent.counterparties.length) {
    if (!child.counterparties || !child.counterparties.length) p.push("counterparties: parent restricts counterparties, delegated mandate must list them");
    else for (const c of child.counterparties) if (!parent.counterparties.some((pc) => counterpartyMatches(pc, normalizeCounterparty(c)))) p.push(`counterparties: ${c} is not covered by the parent mandate`);
  }
  if (parent.payment_instruments && parent.payment_instruments.length) {
    if (!child.payment_instruments || !child.payment_instruments.length) p.push("payment_instruments: parent restricts instruments, delegated mandate must list them");
    else for (const i of child.payment_instruments) if (!parent.payment_instruments.some((pi) => pi.network === i.network && pi.ref_sha256 === i.ref_sha256)) p.push(`payment_instruments: ${i.network} ${i.ref_sha256.slice(0, 12)}… is not in the parent mandate`);
  }
  if (parent.valid_from && (!child.valid_from || Date.parse(child.valid_from) < Date.parse(parent.valid_from))) p.push("valid_from: delegated mandate starts before the parent's");
  if (parent.valid_until && (!child.valid_until || Date.parse(child.valid_until) > Date.parse(parent.valid_until))) p.push("valid_until: delegated mandate ends after the parent's");
  if (child.delegation) {
    if (!parent.delegation) p.push("delegation: parent does not allow further delegation");
    else {
      if (child.delegation.max_depth > parent.delegation.max_depth - 1) p.push(`delegation.max_depth: at most ${parent.delegation.max_depth - 1} below this level`);
      if (child.delegation.max_ttl_seconds > parent.delegation.max_ttl_seconds) p.push(`delegation.max_ttl_seconds: above the parent's ${parent.delegation.max_ttl_seconds}`);
    }
  }
  return p;
}

export function isMandateSubset(parent: Mandate, child: Mandate): boolean {
  return mandateSubsetProblems(parent, child).length === 0;
}

/** Validates a mandate to delegate: the usual schema plus the size limit of delegated mandates. */
export function validateDelegatedMandate(input: unknown): Mandate {
  const m = validateMandate(input);
  if (JSON.stringify(m).length > DELEGATED_MANDATE_MAX_BYTES) throw new KyaError("INVALID_INPUT", `delegated mandate larger than ${DELEGATED_MANDATE_MAX_BYTES} bytes`);
  return m;
}

/** The exact text the delegator signs. */
export async function delegationText(d: Omit<Delegation, "signature" | "version">): Promise<string> {
  return [
    "KYA Brasil: delegation",
    `credential: ${d.credential_id}`,
    `parent: ${d.parent ?? "-"}`,
    `delegate: ${d.delegate.kind}:${d.delegate.id}`,
    `depth: ${d.depth}`,
    `issued: ${d.issued_at}`,
    `expires: ${d.expires_at}`,
    `mandate-sha256: ${await sha256Hex(canonicalize(d.mandate))}`
  ].join("\n");
}

/** Identifier of a signed delegation, used as `parent` by the next one. */
export function delegationRef(d: Pick<Delegation, "signature">): Promise<string> {
  return sha256Hex(d.signature);
}

/**
 * Builds the unsigned delegation that extends `chain` (empty = delegate from the credential itself) and the text
 * to sign. The delegator signs `text` with its key and sets `signature`. Throws INVALID_INPUT when the policy
 * does not allow it (depth, lifetime, mandate not contained in the delegator's).
 */
export async function prepareDelegation(p: { credential: DelegationAnchor; chain?: Delegation[]; delegate: { kind?: unknown; id?: unknown }; mandate: unknown; ttlSeconds: number; now?: Date }): Promise<{ delegation: Omit<Delegation, "signature">; text: string }> {
  const chain = p.chain ?? [];
  const now = p.now ?? new Date();
  const delegate = normalizeAgentKey(p.delegate);
  if (delegate.kind === "erc8004") throw new KyaError("INVALID_INPUT", "delegate must be an evm or web-bot-auth key");
  const mandate = validateDelegatedMandate(p.mandate);
  const last = chain[chain.length - 1];
  const parentMandate = last ? last.mandate : p.credential.mandate;
  const policy = parentMandate.delegation;
  const depth = chain.length + 1;
  if (!policy) throw new KyaError("INVALID_INPUT", depth === 1 ? "the credential's mandate does not allow delegation" : "the delegator's mandate does not allow further delegation");
  if (depth > DELEGATION_MAX_DEPTH) throw new KyaError("INVALID_INPUT", `delegation deeper than ${DELEGATION_MAX_DEPTH}`);
  if (!Number.isInteger(p.ttlSeconds) || p.ttlSeconds < DELEGATION_MIN_TTL_SECONDS || p.ttlSeconds > policy.max_ttl_seconds) throw new KyaError("INVALID_INPUT", `ttlSeconds must be from ${DELEGATION_MIN_TTL_SECONDS} to ${policy.max_ttl_seconds}`);
  const problems = mandateSubsetProblems(parentMandate, mandate);
  if (problems.length) throw new KyaError("INVALID_INPUT", `delegated mandate is broader than the delegator's: ${problems.join("; ")}`);
  let expires = now.getTime() + p.ttlSeconds * 1000;
  for (const bound of [p.credential.expires_at, last?.expires_at]) if (bound) expires = Math.min(expires, Date.parse(bound));
  const delegation: Omit<Delegation, "signature"> = {
    version: 1,
    credential_id: p.credential.credential_id,
    parent: last ? await delegationRef(last) : null,
    delegate,
    depth,
    issued_at: now.toISOString(),
    expires_at: new Date(expires).toISOString(),
    mandate
  };
  return { delegation, text: await delegationText(delegation) };
}

export type DelegationChainResult =
  | { ok: true; delegate: AgentKey; depth: number; expires_at: string; mandates: Mandate[]; ref: string }
  | { ok: false; error: string; message: string };

/**
 * Verifies a delegation chain against its credential, offline: every link signed by the key above it, depth and
 * lifetime within each policy, each mandate contained in the one above, nothing expired. On success `delegate` is
 * the key that must sign the request and `mandates` is every mandate an action must satisfy (credential first).
 * The credential's own status (active, not revoked) is the caller's to check, as for any request.
 */
export async function verifyDelegationChain(p: { credential: DelegationAnchor; chain: unknown; now?: Date }): Promise<DelegationChainResult> {
  const fail = (error: string, message: string): DelegationChainResult => ({ ok: false, error, message });
  const now = (p.now ?? new Date()).getTime();
  if (!Array.isArray(p.chain) || p.chain.length === 0) return fail("KYA_DELEGATION_MALFORMED", "delegation chain must be a non-empty array");
  if (p.chain.length > DELEGATION_MAX_DEPTH) return fail("KYA_DELEGATION_TOO_DEEP", `delegation deeper than ${DELEGATION_MAX_DEPTH}`);
  let signer: AgentKey = p.credential.agent;
  let parentMandate: Mandate = p.credential.mandate;
  let parentRef: string | null = null;
  let notAfter = Date.parse(p.credential.expires_at);
  if (!Number.isFinite(notAfter)) return fail("KYA_DELEGATION_MALFORMED", "the credential has no valid expires_at");
  const mandates: Mandate[] = [p.credential.mandate];
  for (let i = 0; i < p.chain.length; i++) {
    const at = `delegation ${i + 1}`;
    const raw = p.chain[i] as Partial<Delegation> | null;
    if (!raw || typeof raw !== "object" || raw.version !== 1 || typeof raw.signature !== "string" || typeof raw.issued_at !== "string" || typeof raw.expires_at !== "string") return fail("KYA_DELEGATION_MALFORMED", `${at}: not a v1 delegation`);
    if (raw.credential_id !== p.credential.credential_id) return fail("KYA_DELEGATION_MISMATCH", `${at}: issued under another credential`);
    if (raw.depth !== i + 1) return fail("KYA_DELEGATION_MALFORMED", `${at}: depth must be ${i + 1}`);
    if ((raw.parent ?? null) !== parentRef) return fail("KYA_DELEGATION_MISMATCH", `${at}: does not extend the previous link`);
    let delegate: AgentKey;
    let mandate: Mandate;
    try {
      delegate = normalizeAgentKey(raw.delegate ?? {});
      if (delegate.kind === "erc8004") throw new KyaError("INVALID_INPUT", "erc8004 delegate");
      mandate = validateDelegatedMandate(raw.mandate);
    } catch (e) {
      return fail("KYA_DELEGATION_MALFORMED", `${at}: ${(e as Error).message}`);
    }
    if (delegate.id !== raw.delegate?.id || canonicalize(mandate) !== canonicalize(raw.mandate)) return fail("KYA_DELEGATION_MALFORMED", `${at}: delegate or mandate not in normalized form`);
    const policy = parentMandate.delegation;
    if (!policy) return fail("KYA_DELEGATION_NOT_ALLOWED", i === 0 ? "the credential's mandate does not allow delegation" : `${at}: the delegator's mandate does not allow further delegation`);
    const issued = Date.parse(raw.issued_at);
    const expires = Date.parse(raw.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued) return fail("KYA_DELEGATION_MALFORMED", `${at}: bad issued_at / expires_at`);
    if (expires - issued > policy.max_ttl_seconds * 1000) return fail("KYA_DELEGATION_TTL", `${at}: lives longer than ${policy.max_ttl_seconds}s`);
    if (expires > notAfter) return fail("KYA_DELEGATION_TTL", `${at}: outlives the link above it`);
    if (issued > now + SKEW_MS) return fail("KYA_DELEGATION_NOT_YET_VALID", `${at}: issued in the future`);
    if (expires < now) return fail("KYA_DELEGATION_EXPIRED", `${at}: expired at ${raw.expires_at}`);
    const problems = mandateSubsetProblems(parentMandate, mandate);
    if (problems.length) return fail("KYA_DELEGATION_BROADER", `${at}: ${problems.join("; ")}`);
    const text = await delegationText({ credential_id: raw.credential_id, parent: parentRef, delegate, depth: i + 1, issued_at: raw.issued_at, expires_at: raw.expires_at, mandate });
    if (!(await verifyAgentSignature(signer, text, raw.signature))) return fail("KYA_DELEGATION_BAD_SIGNATURE", `${at}: not signed by the key above it`);
    signer = delegate;
    parentMandate = mandate;
    parentRef = await delegationRef({ signature: raw.signature });
    notAfter = expires;
    mandates.push(mandate);
  }
  return { ok: true, delegate: signer, depth: p.chain.length, expires_at: new Date(notAfter).toISOString(), mandates, ref: parentRef as string };
}

/**
 * Evaluates an action against every mandate of a verified chain (credential first). Allowed only when all allow
 * it; `levels[0]` is the credential's mandate, `levels[n]` the mandate of delegation n.
 */
export function checkDelegatedAction(mandates: Mandate[], q: ActionQuery): { allowed: boolean; levels: ActionVerdict[] } {
  const levels = mandates.map((m) => checkAction(m, q));
  return { allowed: levels.length > 0 && levels.every((l) => l.allowed), levels };
}

/** Encodes a chain for the `KYA-Delegation` header (base64url of its JSON). */
export function encodeDelegationHeader(chain: Delegation[]): string {
  const bytes = new TextEncoder().encode(JSON.stringify(chain));
  let s = "";
  for (const b of bytes) s += String.fromCodePoint(b);
  const b64 = btoa(s).replaceAll("+", "-").replaceAll("/", "_");
  let end = b64.length;
  while (end > 0 && b64[end - 1] === "=") end--;
  return b64.slice(0, end);
}

/** Decodes a `KYA-Delegation` header; throws INVALID_INPUT when it is not base64url JSON. */
export function decodeDelegationHeader(value: string): unknown {
  try {
    const b64 = value.trim().replaceAll("-", "+").replaceAll("_", "/");
    const bin = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="));
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.codePointAt(0) ?? 0)));
  } catch {
    throw new KyaError("INVALID_INPUT", "KYA-Delegation is not base64url JSON");
  }
}
