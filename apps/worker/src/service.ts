/**
 * The KYA use cases, independent of HTTP: register (challenge), prove (issue), verify, check
 * an action, renew, revoke, and the daily review. Each returns plain JSON; routes add payment.
 */
import {
  type AgentKey, type Credential, KyaError, type Mandate, buildCredential, checkAction, effectiveStatus, formatCnpj, isValidCnpj, principalDecision, revocationEffect, newChallenge,
  normalizeAgentKey, normalizeCnpj, signCredential, validateMandate, verifyAgentSignature, verifyIcpSignature, challengeText,
  actText, dayOf, spentToday, validateAct
} from "@kya-br/core";
import { icpAnchors } from "./anchors";
import { withWallet } from "./erc8004";
import { material, signAnswer } from "./attest";
import type { AppEnv } from "./env";
import { kybRegistration, kybRiskScreen } from "./kyb";
import { certificateRevocation } from "./revocation";
import { Store, type AgentRow } from "./store";

const issuerOf = (env: AppEnv, origin: string) => (env.ISSUER_URL ?? origin).replace(/\/$/, "");

export async function register(env: AppEnv, origin: string, body: { agent?: unknown; cnpj?: unknown; mandate?: unknown }) {
  // erc8004: the token must exist and its wallet is recorded now (and re-read at proof time).
  const agent = await withWallet(env, normalizeAgentKey((body.agent ?? {}) as { kind?: unknown; id?: unknown }));
  if (typeof body.cnpj !== "string" || !isValidCnpj(body.cnpj)) throw new KyaError("INVALID_CNPJ", "cnpj must be a valid Brazilian CNPJ");
  const cnpj = normalizeCnpj(body.cnpj);
  const mandate = validateMandate(body.mandate ?? {});
  const store = new Store(env.DB);
  const issuer = issuerOf(env, origin);
  let row = await store.findByKey(agent, cnpj);
  if (row && row.status === "active") throw new KyaError("CONFLICT", `this agent key already holds an active credential for CNPJ ${cnpj} (${row.id}); renew or revoke it instead`);
  const id = row?.id ?? crypto.randomUUID();
  if (!row) await store.createAgent({ id, agent, cnpj, mandate });
  else {
    await env.DB.prepare("UPDATE agents SET mandate = ?2, status = 'pending', status_reason = NULL, updated_at = ?3 WHERE id = ?1").bind(id, JSON.stringify(mandate), new Date().toISOString()).run();
    if (agent.wallet) await store.setWallet(id, agent.wallet);
  }
  const ch = newChallenge({ issuer, agent, cnpj });
  await store.createChallenge({ id: ch.challenge_id, agent_row: id, text: ch.text, expires_at: ch.expires_at });
  return {
    credential_id: id,
    agent,
    principal: { cnpj, cnpj_formatted: formatCnpj(cnpj) },
    mandate,
    challenge: { id: ch.challenge_id, text: ch.text, expires_at: ch.expires_at },
    ...(agent.wallet ? { agent_wallet: agent.wallet } : {}),
    next: {
      en: `Sign challenge.text twice: with the agent key (evm: EIP-191 personal_sign hex; web-bot-auth: Ed25519 raw signature, base64url; erc8004: EIP-191 by the on-chain agentWallet ${agent.wallet ?? ""}) and with the company's e-CNPJ (CMS/PKCS#7 SignedData, detached, base64 DER). Then POST ${issuer}/v1/agents/${id}/prove with {challenge_id, agent_signature, ecnpj_signature}.`,
      pt: `Assine challenge.text duas vezes: com a chave do agente (evm: EIP-191 personal_sign em hex; web-bot-auth: assinatura Ed25519 bruta em base64url) e com o e-CNPJ da empresa (CMS/PKCS#7 SignedData, destacado, base64 DER). Depois envie POST ${issuer}/v1/agents/${id}/prove com {challenge_id, agent_signature, ecnpj_signature}.`
    },
    mandate_schema: `${issuer}/.well-known/kya-mandate.schema.json`
  };
}

async function issueFor(env: AppEnv, origin: string, row: AgentRow, proof: { challenge_id: string; agent_signature: string; ecnpj_signature: string }, event: "issued" | "renewed") {
  const store = new Store(env.DB);
  // erc8004: the wallet is read again now, so a transfer between registration and proof is caught.
  const agent: AgentKey = await withWallet(env, { kind: row.agent_kind, id: row.agent_id });
  const ch = await store.takeChallenge(proof.challenge_id, row.id);
  if (!ch) throw new KyaError("CHALLENGE_FAILED", "challenge unknown, expired (15 minutes) or already used; register again");
  if (!(await verifyAgentSignature(agent, ch.text, proof.agent_signature))) throw new KyaError("CHALLENGE_FAILED", "agent_signature does not match the agent key over challenge.text");
  const anchors = await icpAnchors(env);
  const icp = await verifyIcpSignature({ cmsBase64: proof.ecnpj_signature, challenge: ch.text, expectedCnpj: row.cnpj, anchors });
  // D-16: a revoked e-CNPJ authorizes nothing; without a trustworthy CRL nothing is issued (fail closed, like D-08).
  const revocation = await certificateRevocation(env, icp);
  if (revocation.revoked) throw new KyaError("CERTIFICATE_REVOKED", `the e-CNPJ certificate was revoked by its AC on ${revocation.revoked_at}${revocation.reason ? ` (${revocation.reason})` : ""}`);
  // D-15: only the registration status decides; the rest of the screen is informative (kyb_snapshot).
  const kyb = await kybRiskScreen(env, row.cnpj);
  const decision = principalDecision(kyb.snapshot.registration_status);
  if (!decision.ok) {
    await store.setStatus({ id: row.id, status: "suspended", reason: decision.reason, actor: "issuer", cause: "registration", last_kyb_at: kyb.snapshot.checked_at });
    throw new KyaError("KYB_BLOCKED", `credential not issued: ${decision.reason}`);
  }
  const m = await material(env);
  if (!m) throw new KyaError("UPSTREAM_ERROR", "issuer has no signing key");
  const issuer = issuerOf(env, origin);
  const mandate = JSON.parse(row.mandate) as Mandate;
  const certificate = { sha256: icp.certificate_sha256, subject: icp.certificate_subject, issuer: icp.issuer, signed_at: icp.signed_at };
  const unsigned = buildCredential({ credential_id: row.id, agent, cnpj: row.cnpj, legal_name: kyb.legal_name, registration_status: kyb.snapshot.registration_status, certificate, mandate, kyb: kyb.snapshot, issuer });
  const credential = await signCredential(unsigned, m.key, m.keyId);
  const record = { ...certificate, serial_number: icp.serial_number, issuer_certificate: icp.issuer_certificate, crl_urls: icp.crl_urls, revocation_checked_at: new Date().toISOString() };
  await store.issue({ id: row.id, legal_name: kyb.legal_name, credential, certificate: record, mandate, event });
  if (agent.wallet && agent.wallet !== row.agent_wallet) await store.setWallet(row.id, agent.wallet);
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
    agent: { kind: row.agent_kind, id: row.agent_id, ...(row.agent_wallet ? { wallet: row.agent_wallet as `0x${string}` } : {}) } as AgentKey,
    principal: { cnpj: row.cnpj, cnpj_formatted: formatCnpj(row.cnpj), legal_name: row.legal_name },
    credential: credential ? { ...credential, status, status_reason: row.status_reason } : null,
    /** The signature covers the credential as issued; a later status change is reported here and at revocation_url, not re-signed. */
    signature_covers: credential ? "the credential object as issued (status at issuance); check `status` here for the live state" : null,
    events
  };
}

/** What this agent already spent today (UTC) in the mandate's daily currency, from the registered acts. */
async function registeredToday(env: AppEnv, id: string, mandate: Mandate, now: Date): Promise<{ currency: string; amount: number } | null> {
  const currency = mandate.max_per_day?.currency;
  if (!currency) return null;
  const rows = await new Store(env.DB).actsOfDay(id, dayOf(now));
  return { currency, amount: spentToday(rows.map((r) => ({ amount: r.amount, currency: r.currency, allowed: r.allowed === 1 })), currency) };
}

function evaluate(v: Awaited<ReturnType<typeof verify>>, q: { action?: string; amount?: number; currency?: string; counterparty?: string; spent_today?: number }, registered: { currency: string; amount: number } | null, now: Date) {
  const live = v.status === "active";
  const mandate = v.credential?.mandate ?? {};
  // The caller's own count and the issuer's registered acts: the larger one applies.
  const spent = Math.max(q.spent_today ?? 0, registered && (!q.currency || q.currency.toUpperCase() === registered.currency) ? registered.amount : 0);
  const verdict = checkAction(mandate, { action: q.action, amount: q.amount, currency: q.currency, counterparty: q.counterparty, spent_today: spent > 0 ? spent : undefined, now });
  return {
    live,
    verdict,
    allowed: live && verdict.allowed,
    reason: !live ? `credential is ${v.status}${v.status_reason ? `: ${v.status_reason}` : ""}` : verdict.allowed ? "inside the mandate" : verdict.checks.filter((c) => !c.ok).map((c) => c.detail).join("; "),
    spent_today_registered: registered ? { ...registered, note: "sum of the acts registered today in this currency; the verdict uses the larger of this and your spent_today" } : null
  };
}

export async function allowed(env: AppEnv, origin: string, id: string, q: { action?: string; amount?: string; currency?: string; counterparty?: string; spent_today?: string }) {
  const v = await verify(env, id);
  const amount = q.amount !== undefined && q.amount !== "" ? Number(q.amount) : undefined;
  if (amount !== undefined && !Number.isFinite(amount)) throw new KyaError("INVALID_INPUT", "amount must be a number");
  const spent = q.spent_today !== undefined && q.spent_today !== "" ? Number(q.spent_today) : undefined;
  const now = new Date();
  const registered = await registeredToday(env, id, v.credential?.mandate ?? {}, now);
  const e = evaluate(v, { action: q.action, amount, currency: q.currency, counterparty: q.counterparty, spent_today: Number.isFinite(spent) ? spent : undefined }, registered, now);
  const out: Record<string, unknown> = {
    credential_id: id,
    status: v.status,
    allowed: e.allowed,
    reason: e.reason,
    query: { action: q.action ?? null, amount: amount ?? null, currency: q.currency ?? null, counterparty: q.counterparty ?? null },
    checks: e.verdict.checks,
    not_evaluated: e.verdict.not_evaluated,
    spent_today_registered: e.spent_today_registered,
    principal: v.principal,
    agent: v.agent,
    checked_at: now.toISOString()
  };
  const attestation = await signAnswer(env, out, issuerOf(env, origin));
  return attestation ? { ...out, attestation } : out;
}

/**
 * Registers an act: what the agent did, checked against the mandate plus everything registered today,
 * with a signed receipt. Denied acts are recorded too (they are evidence) but do not count as spent.
 */
export async function registerAct(env: AppEnv, origin: string, id: string, body: Record<string, unknown>) {
  const act = validateAct(body);
  const v = await verify(env, id);
  const issuer = issuerOf(env, origin);
  const now = new Date();
  let agent_signed = false;
  if (act.agent_signature) {
    agent_signed = await verifyAgentSignature(v.agent, actText({ issuer, credential_id: id, agent: v.agent, act }), act.agent_signature);
    if (!agent_signed) throw new KyaError("CHALLENGE_FAILED", "agent_signature does not match the agent key over the act text (GET /v1/acts/text for the exact lines)");
  }
  const registered = await registeredToday(env, id, v.credential?.mandate ?? {}, now);
  const e = evaluate(v, { action: act.action, amount: act.amount, currency: act.currency, counterparty: act.counterparty }, registered, now);
  const act_id = crypto.randomUUID();
  const { agent_signature: _s, ...actPublic } = act;
  const body_out: Record<string, unknown> = {
    act_id,
    credential_id: id,
    status: v.status,
    allowed: e.allowed,
    reason: e.reason,
    act: { ...actPublic, registered_by: act.registered_by ?? "counterparty", agent_signed },
    checks: e.verdict.checks,
    not_evaluated: e.verdict.not_evaluated,
    spent_today_registered_before: e.spent_today_registered ? { currency: e.spent_today_registered.currency, amount: e.spent_today_registered.amount } : null,
    spent_today_registered_after: e.spent_today_registered && e.allowed && act.amount !== undefined && act.currency === e.spent_today_registered.currency ? { currency: e.spent_today_registered.currency, amount: e.spent_today_registered.amount + act.amount } : e.spent_today_registered ? { currency: e.spent_today_registered.currency, amount: e.spent_today_registered.amount } : null,
    principal: v.principal,
    agent: v.agent,
    registered_at: now.toISOString(),
    receipt_url: `${issuer}/v1/acts/${act_id}`
  };
  const attestation = await signAnswer(env, body_out, issuer);
  const receipt = attestation ? { ...body_out, attestation } : body_out;
  await new Store(env.DB).createAct({
    id: act_id, agent_row: id, day: dayOf(now), action: act.action, amount: act.amount ?? null, currency: act.currency ?? null, counterparty: act.counterparty ?? null,
    reference: act.reference ?? null, content_sha256: act.content_sha256 ?? null, registered_by: act.registered_by ?? "counterparty", registrant: act.registrant ?? null,
    agent_signed: agent_signed ? 1 : 0, allowed: e.allowed ? 1 : 0, receipt: JSON.stringify(receipt)
  });
  return receipt;
}

export async function getAct(env: AppEnv, actId: string) {
  const row = await new Store(env.DB).getAct(actId);
  if (!row) throw new KyaError("NOT_FOUND", "unknown act_id");
  return JSON.parse(row.receipt) as Record<string, unknown>;
}

/** The exact text an agent signs for an act (so clients do not have to reimplement it). */
export async function actTextFor(env: AppEnv, origin: string, id: string, body: Record<string, unknown>) {
  const act = validateAct(body);
  const v = await verify(env, id);
  return { credential_id: id, agent: v.agent, text: actText({ issuer: issuerOf(env, origin), credential_id: id, agent: v.agent, act }) };
}

/** The company reads the trail of its agent: request signed with the e-CNPJ over "KYA Brasil: acts <id>\n<nonce>". */
export async function exportActs(env: AppEnv, id: string, body: { signed_text?: unknown; ecnpj_signature?: unknown; since?: unknown }) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (typeof body.ecnpj_signature !== "string" || typeof body.signed_text !== "string") throw new KyaError("INVALID_INPUT", "signed_text and ecnpj_signature are required");
  if (!new RegExp(`^KYA Brasil: acts ${id}\\n`).test(body.signed_text)) throw new KyaError("INVALID_INPUT", `signed_text must start with "KYA Brasil: acts ${id}" followed by a newline and a nonce`);
  const icp = await verifyIcpSignature({ cmsBase64: body.ecnpj_signature, challenge: body.signed_text, expectedCnpj: row.cnpj, anchors: await icpAnchors(env) });
  // The trail is the company's: a revoked (e.g. stolen) e-CNPJ does not read it (D-16).
  const revocation = await certificateRevocation(env, icp);
  if (revocation.revoked) throw new KyaError("CERTIFICATE_REVOKED", `the e-CNPJ certificate was revoked by its AC on ${revocation.revoked_at}`);
  const since = typeof body.since === "string" && !Number.isNaN(Date.parse(body.since)) ? new Date(body.since).toISOString() : new Date(Date.now() - 30 * 86400_000).toISOString();
  const acts = await store.acts(id, since);
  return {
    credential_id: id, since, count: acts.length,
    acts: acts.map((a) => ({ act_id: a.id, ts: a.ts, action: a.action, amount: a.amount, currency: a.currency, counterparty: a.counterparty, reference: a.reference, content_sha256: a.content_sha256, registered_by: a.registered_by, registrant: a.registrant, agent_signed: a.agent_signed === 1, allowed: a.allowed === 1, receipt_url: `/v1/acts/${a.id}` }))
  };
}

/** Renewal: new challenge (company re-signs), then the same issuance path. Two steps like registration. */
export async function renewChallenge(env: AppEnv, origin: string, id: string) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (row.status === "revoked") throw new KyaError("CONFLICT", "revoked credentials cannot be renewed; register again");
  const agent: AgentKey = await withWallet(env, { kind: row.agent_kind, id: row.agent_id });
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

/**
 * Daily review of every live credential, on the two things the issuer answers for (D-15, D-16):
 *   - the e-CNPJ that authorized it: revoked at its AC → the credential is revoked (permanent), on hold
 *     → suspended; a later benign replacement of the certificate changes nothing (revocationEffect);
 *   - the company: registration no longer ATIVA → suspended; ATIVA again → reinstated.
 * ERC-8004 credentials are also suspended when the on-chain wallet changes (register again).
 * An unreachable CRL or KYB changes nothing; it is counted in `errors` and retried the next day.
 */
export async function dailyReview(env: AppEnv): Promise<{ reviewed: number; suspended: number; reinstated: number; revoked: number; errors: number }> {
  const store = new Store(env.DB);
  const rows = await store.dueForReview();
  let suspended = 0, reinstated = 0, revoked = 0, errors = 0;
  for (const row of rows) {
    try {
      // erc8004: a credential never outlives a wallet change on chain.
      if (row.agent_kind === "erc8004" && row.status === "active") {
        const live = await withWallet(env, { kind: "erc8004", id: row.agent_id }).catch(() => null);
        if (live && row.agent_wallet && live.wallet !== row.agent_wallet) {
          await store.setStatus({ id: row.id, status: "suspended", reason: `agent wallet changed on chain (${row.agent_wallet} → ${live.wallet}); register again`, actor: "cron", cause: "wallet" });
          suspended++;
          continue;
        }
      }
      // Credentials issued before D-16 carry no CRL data; they expire within 90 days and renew with it.
      let certificate: "none" | "suspend" | "revoke" | "unknown" = "none";
      let certificateReason: string | null = null;
      if (row.certificate_serial) {
        const r = await certificateRevocation(env, { serial_number: row.certificate_serial, issuer_certificate: row.certificate_issuer_der, crl_urls: JSON.parse(row.certificate_crl_urls ?? "[]") as string[] }).catch((e: unknown) => {
          errors++;
          console.error("revocation check failed", row.id, e);
          return null;
        });
        certificate = r ? revocationEffect(r, row.authorized_at) : "unknown";
        if (r?.revoked) certificateReason = `e-CNPJ certificate revoked by its AC on ${r.revoked_at}${r.reason ? ` (${r.reason})` : ""}`;
        if (r) await store.markReviewed(row.id, { last_revocation_check_at: new Date().toISOString() });
      }
      if (certificate === "revoke") {
        await store.setStatus({ id: row.id, status: "revoked", reason: certificateReason, actor: "cron" });
        revoked++;
        continue;
      }
      const reg = await kybRegistration(env, row.cnpj);
      const d = principalDecision(reg.registration_status);
      const hold: { cause: "certificate" | "registration"; reason: string } | null =
        certificate === "suspend" ? { cause: "certificate", reason: certificateReason ?? "e-CNPJ certificate on hold at its AC" } : !d.ok ? { cause: "registration", reason: d.reason ?? "registration not ATIVA" } : null;
      // Reinstate only what this review suspended, and only when the cause is known to be gone.
      const canLift = row.suspension_cause !== "wallet" && !(row.suspension_cause === "certificate" && certificate === "unknown");
      if (row.status === "active" && hold) {
        await store.setStatus({ id: row.id, status: "suspended", reason: hold.reason, actor: "cron", cause: hold.cause, last_kyb_at: reg.checked_at });
        suspended++;
      } else if (row.status === "suspended" && !hold && canLift) {
        // Also lifts suspensions made under the old KYB rules (sanctions, risk), which no longer apply (D-15).
        await store.setStatus({ id: row.id, status: "active", reason: null, actor: "cron", last_kyb_at: reg.checked_at });
        reinstated++;
      } else {
        await store.markReviewed(row.id, { last_kyb_at: reg.checked_at });
      }
    } catch (e) {
      errors++;
      console.error("review failed", row.id, e);
    }
  }
  return { reviewed: rows.length, suspended, reinstated, revoked, errors };
}

export { challengeText };
