/**
 * The KYA use cases, independent of HTTP: register (challenge), prove (issue), verify, check
 * an action, renew, revoke, and the daily review. Each returns plain JSON; routes add payment.
 */
import {
  type AgentKey, type Credential, KyaError, type Mandate, buildCredential, checkAction, effectiveStatus, formatCnpj, isValidCnpj, kybDecision, newChallenge,
  normalizeAgentKey, normalizeCnpj, signCredential, validateMandate, verifyAgentSignature, verifyIcpSignature, challengeText
} from "@kya-br/core";
import { icpAnchors } from "./anchors";
import { material, signAnswer } from "./attest";
import type { AppEnv } from "./env";
import { kybRiskScreen } from "./kyb";
import { Store, type AgentRow } from "./store";

const issuerOf = (env: AppEnv, origin: string) => (env.ISSUER_URL ?? origin).replace(/\/$/, "");

export async function register(env: AppEnv, origin: string, body: { agent?: unknown; cnpj?: unknown; mandate?: unknown }) {
  const agent = normalizeAgentKey((body.agent ?? {}) as { kind?: unknown; id?: unknown });
  if (typeof body.cnpj !== "string" || !isValidCnpj(body.cnpj)) throw new KyaError("INVALID_CNPJ", "cnpj must be a valid Brazilian CNPJ");
  const cnpj = normalizeCnpj(body.cnpj);
  const mandate = validateMandate(body.mandate ?? {});
  const store = new Store(env.DB);
  const issuer = issuerOf(env, origin);
  let row = await store.findByKey(agent, cnpj);
  if (row && row.status === "active") throw new KyaError("CONFLICT", `this agent key already holds an active credential for CNPJ ${cnpj} (${row.id}); renew or revoke it instead`);
  const id = row?.id ?? crypto.randomUUID();
  if (!row) await store.createAgent({ id, agent, cnpj, mandate });
  else await env.DB.prepare("UPDATE agents SET mandate = ?2, status = 'pending', status_reason = NULL, updated_at = ?3 WHERE id = ?1").bind(id, JSON.stringify(mandate), new Date().toISOString()).run();
  const ch = newChallenge({ issuer, agent, cnpj });
  await store.createChallenge({ id: ch.challenge_id, agent_row: id, text: ch.text, expires_at: ch.expires_at });
  return {
    credential_id: id,
    agent,
    principal: { cnpj, cnpj_formatted: formatCnpj(cnpj) },
    mandate,
    challenge: { id: ch.challenge_id, text: ch.text, expires_at: ch.expires_at },
    next: {
      en: `Sign challenge.text twice: with the agent key (evm: EIP-191 personal_sign hex; web-bot-auth: Ed25519 raw signature, base64url) and with the company's e-CNPJ (CMS/PKCS#7 SignedData, detached, base64 DER). Then POST ${issuer}/v1/agents/${id}/prove with {challenge_id, agent_signature, ecnpj_signature}.`,
      pt: `Assine challenge.text duas vezes: com a chave do agente (evm: EIP-191 personal_sign em hex; web-bot-auth: assinatura Ed25519 bruta em base64url) e com o e-CNPJ da empresa (CMS/PKCS#7 SignedData, destacado, base64 DER). Depois envie POST ${issuer}/v1/agents/${id}/prove com {challenge_id, agent_signature, ecnpj_signature}.`
    },
    mandate_schema: `${issuer}/.well-known/kya-mandate.schema.json`
  };
}

async function issueFor(env: AppEnv, origin: string, row: AgentRow, proof: { challenge_id: string; agent_signature: string; ecnpj_signature: string }, event: "issued" | "renewed") {
  const store = new Store(env.DB);
  const agent: AgentKey = { kind: row.agent_kind, id: row.agent_id };
  const ch = await store.takeChallenge(proof.challenge_id, row.id);
  if (!ch) throw new KyaError("CHALLENGE_FAILED", "challenge unknown, expired (15 minutes) or already used; register again");
  if (!(await verifyAgentSignature(agent, ch.text, proof.agent_signature))) throw new KyaError("CHALLENGE_FAILED", "agent_signature does not match the agent key over challenge.text");
  const anchors = await icpAnchors(env);
  const icp = await verifyIcpSignature({ cmsBase64: proof.ecnpj_signature, challenge: ch.text, expectedCnpj: row.cnpj, anchors });
  const kyb = await kybRiskScreen(env, row.cnpj);
  const decision = kybDecision(kyb.snapshot);
  if (!decision.ok) {
    await store.setStatus({ id: row.id, status: "suspended", reason: decision.reason, actor: "issuer", last_kyb_at: kyb.snapshot.checked_at });
    throw new KyaError("KYB_BLOCKED", `credential not issued: ${decision.reason}`);
  }
  const m = await material(env);
  if (!m) throw new KyaError("UPSTREAM_ERROR", "issuer has no signing key");
  const issuer = issuerOf(env, origin);
  const mandate = JSON.parse(row.mandate) as Mandate;
  const certificate = { sha256: icp.certificate_sha256, subject: icp.certificate_subject, issuer: icp.issuer, signed_at: icp.signed_at };
  const unsigned = buildCredential({ credential_id: row.id, agent, cnpj: row.cnpj, legal_name: kyb.legal_name, registration_status: kyb.snapshot.registration_status, certificate, mandate, kyb: kyb.snapshot, issuer });
  const credential = await signCredential(unsigned, m.key, m.keyId);
  await store.issue({ id: row.id, legal_name: kyb.legal_name, credential, certificate, mandate, event });
  return { credential, kyb_warnings: kyb.warnings };
}

export async function prove(env: AppEnv, origin: string, id: string, body: { challenge_id?: unknown; agent_signature?: unknown; ecnpj_signature?: unknown }) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (row.status === "active") throw new KyaError("CONFLICT", "credential already active; use renew");
  const proof = proofFrom(body);
  return issueFor(env, origin, row, proof, "issued");
}

function proofFrom(body: { challenge_id?: unknown; agent_signature?: unknown; ecnpj_signature?: unknown }) {
  for (const k of ["challenge_id", "agent_signature", "ecnpj_signature"] as const) if (typeof body[k] !== "string" || !(body[k] as string).length) throw new KyaError("INVALID_INPUT", `${k} is required`);
  return { challenge_id: body.challenge_id as string, agent_signature: body.agent_signature as string, ecnpj_signature: body.ecnpj_signature as string };
}

/** Current credential with effective status (expiry applied) and the event history. */
export async function verify(env: AppEnv, id: string) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  return present(row, await store.events(id));
}

export async function verifyByKey(env: AppEnv, kind: unknown, keyId: unknown) {
  const agent = normalizeAgentKey({ kind, id: keyId });
  const store = new Store(env.DB);
  const rows = await store.findActiveByKey(agent);
  return { agent, credentials: await Promise.all(rows.map(async (r) => present(r, await store.events(r.id)))) };
}

function present(row: AgentRow, events: { ts: string; event: string; reason: string | null; actor: string }[]) {
  const credential = row.credential ? (JSON.parse(row.credential) as Credential) : null;
  const status = credential ? effectiveStatus({ status: row.status, expires_at: row.expires_at ?? credential.expires_at }) : row.status;
  return {
    credential_id: row.id,
    status,
    status_reason: row.status_reason,
    agent: { kind: row.agent_kind, id: row.agent_id },
    principal: { cnpj: row.cnpj, cnpj_formatted: formatCnpj(row.cnpj), legal_name: row.legal_name },
    credential: credential ? { ...credential, status, status_reason: row.status_reason } : null,
    /** The signature covers the credential as issued; a later status change is reported here and at revocation_url, not re-signed. */
    signature_covers: credential ? "the credential object as issued (status at issuance); check `status` here for the live state" : null,
    events
  };
}

export async function allowed(env: AppEnv, origin: string, id: string, q: { action?: string; amount?: string; currency?: string; counterparty?: string; spent_today?: string }) {
  const v = await verify(env, id);
  const live = v.status === "active";
  const mandate = v.credential?.mandate ?? {};
  const amount = q.amount !== undefined && q.amount !== "" ? Number(q.amount) : undefined;
  if (amount !== undefined && !Number.isFinite(amount)) throw new KyaError("INVALID_INPUT", "amount must be a number");
  const spent = q.spent_today !== undefined && q.spent_today !== "" ? Number(q.spent_today) : undefined;
  const verdict = checkAction(mandate, { action: q.action, amount, currency: q.currency, counterparty: q.counterparty, spent_today: Number.isFinite(spent) ? spent : undefined });
  const out: Record<string, unknown> = {
    credential_id: id,
    status: v.status,
    allowed: live && verdict.allowed,
    reason: !live ? `credential is ${v.status}${v.status_reason ? `: ${v.status_reason}` : ""}` : verdict.allowed ? "inside the mandate" : verdict.checks.filter((c) => !c.ok).map((c) => c.detail).join("; "),
    query: { action: q.action ?? null, amount: amount ?? null, currency: q.currency ?? null, counterparty: q.counterparty ?? null },
    checks: verdict.checks,
    not_evaluated: verdict.not_evaluated,
    principal: v.principal,
    agent: v.agent,
    checked_at: new Date().toISOString()
  };
  const attestation = await signAnswer(env, out, issuerOf(env, origin));
  return attestation ? { ...out, attestation } : out;
}

/** Renewal: new challenge (company re-signs), then the same issuance path. Two steps like registration. */
export async function renewChallenge(env: AppEnv, origin: string, id: string) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (row.status === "revoked") throw new KyaError("CONFLICT", "revoked credentials cannot be renewed; register again");
  const agent: AgentKey = { kind: row.agent_kind, id: row.agent_id };
  const ch = newChallenge({ issuer: issuerOf(env, origin), agent, cnpj: row.cnpj });
  await store.createChallenge({ id: ch.challenge_id, agent_row: id, text: ch.text, expires_at: ch.expires_at });
  return { credential_id: id, challenge: { id: ch.challenge_id, text: ch.text, expires_at: ch.expires_at }, next: `POST ${issuerOf(env, origin)}/v1/agents/${id}/renew/prove with {challenge_id, agent_signature, ecnpj_signature}` };
}

export async function renewProve(env: AppEnv, origin: string, id: string, body: { challenge_id?: unknown; agent_signature?: unknown; ecnpj_signature?: unknown }) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (row.status === "revoked") throw new KyaError("CONFLICT", "revoked credentials cannot be renewed");
  return issueFor(env, origin, row, proofFrom(body), "renewed");
}

/** Revocation: the company signs "revoke <credential_id> <nonce>" with its e-CNPJ; no agent signature needed. */
export async function revoke(env: AppEnv, id: string, body: { reason?: unknown; ecnpj_signature?: unknown; signed_text?: unknown }) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (row.status === "revoked") return { credential_id: id, status: "revoked", already: true };
  if (typeof body.ecnpj_signature !== "string" || typeof body.signed_text !== "string") throw new KyaError("INVALID_INPUT", "signed_text and ecnpj_signature are required");
  if (!new RegExp(`^KYA Brasil: revoke ${id}\\n`).test(body.signed_text)) throw new KyaError("INVALID_INPUT", `signed_text must start with "KYA Brasil: revoke ${id}" followed by a newline and a nonce`);
  await verifyIcpSignature({ cmsBase64: body.ecnpj_signature, challenge: body.signed_text, expectedCnpj: row.cnpj, anchors: await icpAnchors(env) });
  const reason = typeof body.reason === "string" ? body.reason.slice(0, 200) : "revoked by the company";
  await store.setStatus({ id, status: "revoked", reason, actor: "company" });
  return { credential_id: id, status: "revoked", reason, revoked_at: new Date().toISOString() };
}

/** Daily review: re-run KYB on every live credential; suspend what no longer clears, reinstate what does. */
export async function dailyReview(env: AppEnv): Promise<{ reviewed: number; suspended: number; reinstated: number; errors: number }> {
  const store = new Store(env.DB);
  const rows = await store.dueForReview();
  let suspended = 0, reinstated = 0, errors = 0;
  for (const row of rows) {
    try {
      const kyb = await kybRiskScreen(env, row.cnpj);
      const d = kybDecision(kyb.snapshot);
      if (row.status === "active" && !d.ok) {
        await store.setStatus({ id: row.id, status: "suspended", reason: d.reason, actor: "cron", last_kyb_at: kyb.snapshot.checked_at });
        suspended++;
      } else if (row.status === "suspended" && d.ok) {
        await store.setStatus({ id: row.id, status: "active", reason: null, actor: "cron", last_kyb_at: kyb.snapshot.checked_at });
        reinstated++;
      } else {
        await env.DB.prepare("UPDATE agents SET last_kyb_at = ?2 WHERE id = ?1").bind(row.id, kyb.snapshot.checked_at).run();
      }
    } catch (e) {
      errors++;
      console.error("review failed", row.id, e);
    }
  }
  return { reviewed: rows.length, suspended, reinstated, errors };
}

export { challengeText };
