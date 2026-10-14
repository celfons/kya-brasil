/**
 * The KYA use cases, independent of HTTP: register (challenge), prove (issue), verify, check
 * an action, renew, revoke, and the daily review. Each returns plain JSON; routes add payment.
 */
import {
  type AgentKey, type Credential, KyaError, type Mandate, buildCredential, checkAction, effectiveStatus, formatCnpj, isValidCnpj, principalDecision, revocationEffect, newChallenge,
  normalizeAgentKey, normalizeCnpj, signCredential, signingLink, validateMandate, verifyAgentSignature, verifyIcpSignature, challengeText,
} from "@kya-brasil/core";
import { icpAnchors } from "./anchors";
import { withWallet } from "./erc8004";
import { material, signAnswer } from "./attest";
import type { AppEnv } from "./env";
import { notifyCompany } from "./company";
import { registrationOrWarning } from "./registration";
import { certificateRevocation } from "./revocation";
import { Store, type AgentRow } from "./store";
import { issuePerson, keysOf, personChallenge, revokePerson } from "./person";

const issuerOf = (env: AppEnv, origin: string) => (env.ISSUER_URL ?? origin).replace(/\/$/, "");

export async function register(env: AppEnv, origin: string, body: { agent?: unknown; cnpj?: unknown; mandate?: unknown; principal?: unknown }) {
  // erc8004: the token must exist and its wallet is recorded now (and re-read at proof time).
  const agent = await withWallet(env, normalizeAgentKey((body.agent ?? {}) as { kind?: unknown; id?: unknown }));
  if (body.principal === "person") return registerPerson(env, origin, agent, body);
  if (body.principal !== undefined && body.principal !== "company") throw new KyaError("INVALID_INPUT", 'principal must be "company" (default) or "person"');
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
      en: `Sign challenge.text twice: with the agent key (evm: EIP-191 personal_sign hex; web-bot-auth: Ed25519 raw signature, base64url; erc8004: EIP-191 by the on-chain agentWallet ${agent.wallet ?? ""}) and with the company's e-CNPJ (CMS/PKCS#7 SignedData, detached, base64 DER). Then POST ${issuer}/v1/agents/${id}/prove with {challenge_id, agent_signature, ecnpj_signature}. Easiest for the person with the e-CNPJ: sign_url with &agent_signature=<the agent's signature> appended; they sign in the browser (.pfx, or a .p7s from any ICP-Brasil signer) and the credential is issued.`,
      pt: `Assine challenge.text duas vezes: com a chave do agente (evm: EIP-191 personal_sign em hex; web-bot-auth: assinatura Ed25519 bruta em base64url) e com o e-CNPJ da empresa (CMS/PKCS#7 SignedData, destacado, base64 DER). Depois envie POST ${issuer}/v1/agents/${id}/prove com {challenge_id, agent_signature, ecnpj_signature}. Mais fácil para quem tem o e-CNPJ: abrir sign_url com &agent_signature=<assinatura do agente> no final; assina no navegador (.pfx, ou .p7s de qualquer assinador ICP-Brasil) e a credencial é emitida.`
    },
    mandate_schema: `${issuer}/.well-known/kya-mandate.schema.json`,
    /** Page for the e-CNPJ holder (owner or accountant): signs in the browser and issues. Append &agent_signature=… once the agent signed. */
    sign_url: signUrl(issuer, id, ch.challenge_id, ch.text)
  };
}

/** D-29: a natural person registers an agent; the CPF comes later, from the e-CPF that signs the challenge. */
async function registerPerson(env: AppEnv, origin: string, agent: AgentKey, body: { cnpj?: unknown; mandate?: unknown }) {
  keysOf(env); // fail closed before taking anything when this issuer has no person keys
  if (body.cnpj !== undefined) throw new KyaError("INVALID_INPUT", "a person registration has no cnpj");
  const mandate = validateMandate(body.mandate ?? {});
  const store = new Store(env.DB);
  const issuer = issuerOf(env, origin);
  const row = await store.findByKey(agent, "");
  if (row && row.status === "active") throw new KyaError("CONFLICT", `this agent key already holds an active person credential (${row.id}); renew or revoke it instead`);
  const id = row?.id ?? crypto.randomUUID();
  if (!row) await store.createAgent({ id, agent, cnpj: "", mandate, principal_kind: "person" });
  else await env.DB.prepare("UPDATE agents SET mandate = ?2, status = 'pending', status_reason = NULL, updated_at = ?3 WHERE id = ?1").bind(id, JSON.stringify(mandate), new Date().toISOString()).run();
  const ch = personChallenge(issuer, agent);
  await store.createChallenge({ id: ch.challenge_id, agent_row: id, text: ch.text, expires_at: ch.expires_at });
  return {
    credential_id: id,
    agent,
    principal: { kind: "person" },
    mandate,
    challenge: { id: ch.challenge_id, text: ch.text, expires_at: ch.expires_at },
    next: {
      en: `Sign challenge.text twice: with the agent key and with the person's e-CPF (CMS/PKCS#7, base64 DER; the text includes the consent to keep a keyed hash of the CPF). Then POST ${issuer}/v1/agents/${id}/prove with {challenge_id, agent_signature, ecnpj_signature: <the e-CPF signature>}, or send sign_url with &agent_signature=… to the person.`,
      pt: `Assine challenge.text duas vezes: com a chave do agente e com o e-CPF da pessoa (CMS/PKCS#7, base64 DER; o texto inclui o consentimento para guardar um hash com chave do CPF). Depois POST ${issuer}/v1/agents/${id}/prove com {challenge_id, agent_signature, ecnpj_signature: <assinatura do e-CPF>}, ou envie sign_url com &agent_signature=… para a pessoa.`
    },
    mandate_schema: `${issuer}/.well-known/kya-mandate.schema.json`,
    sign_url: signUrl(issuer, id, ch.challenge_id, ch.text)
  };
}

/** The company name in an e-CNPJ subject ("CN=ACME LTDA:11222333000181, ..."), used when the registration is unknown. */
const certificateName = (subject: string) => /CN=([^:,]+)/.exec(subject)?.[1]?.trim() ?? "";

async function issueFor(env: AppEnv, origin: string, row: AgentRow, proof: { challenge_id: string; agent_signature: string; ecnpj_signature: string }, event: "issued" | "renewed") {
  const store = new Store(env.DB);
  // erc8004: the wallet is read again now, so a transfer between registration and proof is caught.
  const agent: AgentKey = await withWallet(env, { kind: row.agent_kind, id: row.agent_id });
  const ch = await store.takeChallenge(proof.challenge_id, row.id);
  if (!ch) throw new KyaError("CHALLENGE_FAILED", "challenge unknown, expired (15 minutes) or already used; register again");
  if (!(await verifyAgentSignature(agent, ch.text, proof.agent_signature))) throw new KyaError("CHALLENGE_FAILED", "agent_signature does not match the agent key over challenge.text");
  if (row.principal_kind === "person") {
    const issued = await issuePerson(env, issuerOf(env, origin), row, agent, ch.text, proof.ecnpj_signature, event);
    if (agent.wallet && agent.wallet !== row.agent_wallet) await store.setWallet(row.id, agent.wallet);
    return issued;
  }
  const anchors = await icpAnchors(env);
  const icp = await verifyIcpSignature({ cmsBase64: proof.ecnpj_signature, challenge: ch.text, expectedCnpj: row.cnpj, anchors });
  // D-16: a revoked e-CNPJ authorizes nothing; without a trustworthy CRL nothing is issued (fail closed, like D-08).
  const revocation = await certificateRevocation(env, icp);
  if (revocation.revoked) throw new KyaError("CERTIFICATE_REVOKED", `the e-CNPJ certificate was revoked by its AC on ${revocation.revoked_at}${revocation.reason ? ` (${revocation.reason})` : ""}`);
  // D-15: only the registration status decides; it comes from the Receita's open data (D-23). D-24: the check is
  // optional and never blocks on its own failure: unknown becomes UNVERIFIED / NOT_CHECKED plus a warning.
  // The /v1 credential keeps its kyb_snapshot field, always null since D-23.
  const reg = await registrationOrWarning(env, row.cnpj);
  const decision = principalDecision(reg.registration_status);
  if (!decision.ok) {
    await store.setStatus({ id: row.id, status: "suspended", reason: decision.reason, actor: "issuer", cause: "registration", last_kyb_at: reg.checked_at ?? undefined });
    // Error code kept for /v1 compatibility: it means "company not ATIVA at the Receita".
    throw new KyaError("KYB_BLOCKED", `credential not issued: ${decision.reason}`);
  }
  const m = await material(env);
  if (!m) throw new KyaError("UPSTREAM_ERROR", "issuer has no signing key");
  const issuer = issuerOf(env, origin);
  const mandate = JSON.parse(row.mandate) as Mandate;
  const certificate = { sha256: icp.certificate_sha256, subject: icp.certificate_subject, issuer: icp.issuer, signed_at: icp.signed_at };
  const legalName = reg.legal_name ?? certificateName(icp.certificate_subject);
  const unsigned = buildCredential({ credential_id: row.id, agent, cnpj: row.cnpj, legal_name: legalName, registration_status: reg.registration_status, certificate, mandate, kyb: null, issuer });
  const credential = await signCredential(unsigned, m.key, m.keyId);
  const record = { ...certificate, serial_number: icp.serial_number, issuer_certificate: icp.issuer_certificate, crl_urls: icp.crl_urls, revocation_checked_at: new Date().toISOString() };
  await store.issue({ id: row.id, legal_name: legalName, credential, certificate: record, mandate, event });
  if (agent.wallet && agent.wallet !== row.agent_wallet) await store.setWallet(row.id, agent.wallet);
  await notifyCompany(env, issuer, row.cnpj, event === "issued" ? "credential.issued" : "credential.renewed", { credential_id: row.id, agent, expires_at: credential.expires_at, certificate_sha256: icp.certificate_sha256 });
  // warnings (D-24); kyb_warnings repeats them for /v1 compatibility.
  const warnings = reg.warning ? [reg.warning] : [];
  return { credential, warnings, kyb_warnings: warnings };
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

/** <issuer>/sign link for the e-CNPJ holder: signingLink from @kya-brasil/core, the same the npm client uses. */
function signUrl(issuer: string, id: string, challengeId: string, text: string, agentSignature?: string): string {
  return signingLink({ issuer, credentialId: id, challenge: { id: challengeId, text }, agentSignature });
}

/** kya_sign_link: the signing link with the agent's signature, from the stored challenge (not consumed). */
export async function signLink(env: AppEnv, origin: string, id: string, q: { challenge_id?: string; agent_signature?: string }) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (!q.challenge_id) throw new KyaError("INVALID_INPUT", "challenge_id is required");
  const ch = await store.peekChallenge(q.challenge_id, row.id);
  if (!ch) throw new KyaError("CHALLENGE_FAILED", "challenge unknown, expired (15 minutes) or already used; register or renew again");
  const agentSignature = q.agent_signature?.trim() || undefined;
  if (agentSignature && agentSignature.length > 600) throw new KyaError("INVALID_INPUT", "agent_signature too long");
  return {
    credential_id: row.id,
    challenge_id: ch.id,
    expires_at: ch.expires_at,
    sign_url: signUrl(issuerOf(env, origin), row.id, ch.id, ch.text, agentSignature),
    for_whom: "the person holding the company's e-CNPJ (owner or accountant); never ask for the certificate or its password yourself",
    terminal: "npx -p @kya-brasil/agent-tools kya-sign --pfx empresa.pfx --link '<sign_url>'   (A3 token: --pkcs11 <vendor library>)"
  };
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
    principal: row.principal_kind === "person" ? { kind: "person" as const, verified_by: "icp-brasil-e-cpf" as const } : { cnpj: row.cnpj, cnpj_formatted: formatCnpj(row.cnpj), legal_name: row.legal_name },
    credential: credential ? { ...credential, status, status_reason: row.status_reason } : null,
    /** While pending: the mandate the company is being asked to sign (shown on the /sign page). */
    ...(credential ? {} : { requested_mandate: JSON.parse(row.mandate) as Mandate }),
    /** The signature covers the credential as issued; a later status change is reported here and at revocation_url, not re-signed. */
    signature_covers: credential ? "the credential object as issued (status at issuance); check `status` here for the live state" : null,
    events
  };
}

/**
 * The mandate verdict for one action. `max_per_day` is evaluated with the `spent_today` the caller gives: the
 * issuer keeps no record of what agents do (D-19), so the daily ceiling is the verifier's or the agent
 * platform's count, never a guarantee across counterparties.
 */
type EvalQuery = { action?: string; amount?: number; currency?: string; counterparty?: string; spent_today?: number; payment_network?: string; payment_ref_sha256?: string };

function evaluate(v: Awaited<ReturnType<typeof verify>>, q: EvalQuery, now: Date) {
  const live = v.status === "active";
  const mandate = v.credential?.mandate ?? {};
  const verdict = checkAction(mandate, { ...q, now });
  let reason = "inside the mandate";
  if (!live) reason = `credential is ${v.status}${v.status_reason ? `: ${v.status_reason}` : ""}`;
  else if (!verdict.allowed) reason = verdict.checks.filter((c) => !c.ok).map((c) => c.detail).join("; ");
  return { live, verdict, allowed: live && verdict.allowed, reason };
}

export async function allowed(env: AppEnv, origin: string, id: string, q: { action?: string; amount?: string; currency?: string; counterparty?: string; spent_today?: string; payment_network?: string; payment_ref_sha256?: string }) {
  const v = await verify(env, id);
  const amount = q.amount !== undefined && q.amount !== "" ? Number(q.amount) : undefined;
  if (amount !== undefined && !Number.isFinite(amount)) throw new KyaError("INVALID_INPUT", "amount must be a number");
  const spent = q.spent_today !== undefined && q.spent_today !== "" ? Number(q.spent_today) : undefined;
  if (spent !== undefined && !Number.isFinite(spent)) throw new KyaError("INVALID_INPUT", "spent_today must be a number");
  // D-25: only the hash of the payment reference ever reaches the issuer; a raw card number is refused.
  const payRef = q.payment_ref_sha256?.trim().toLowerCase() || undefined;
  if (payRef !== undefined && !/^[0-9a-f]{64}$/.test(payRef)) throw new KyaError("INVALID_INPUT", "payment_ref_sha256 must be the 64-hex SHA-256 of the payment reference (never a card number)");
  const payNet = q.payment_network?.trim().toLowerCase() || undefined;
  const now = new Date();
  const e = evaluate(v, { action: q.action, amount, currency: q.currency, counterparty: q.counterparty, spent_today: spent, payment_network: payNet, payment_ref_sha256: payRef }, now);
  const out: Record<string, unknown> = {
    credential_id: id,
    status: v.status,
    allowed: e.allowed,
    reason: e.reason,
    query: { action: q.action ?? null, amount: amount ?? null, currency: q.currency ?? null, counterparty: q.counterparty ?? null, spent_today: spent ?? null, payment_network: payNet ?? null, payment_ref_sha256: payRef ?? null },
    checks: e.verdict.checks,
    not_evaluated: e.verdict.not_evaluated,
    /** Kept in /v1 for compatibility; always null since D-19 (the issuer no longer records acts). */
    spent_today_registered: null,
    principal: v.principal,
    agent: v.agent,
    checked_at: now.toISOString()
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
  const agent: AgentKey = await withWallet(env, { kind: row.agent_kind, id: row.agent_id });
  const ch = row.principal_kind === "person" ? personChallenge(issuerOf(env, origin), agent) : newChallenge({ issuer: issuerOf(env, origin), agent, cnpj: row.cnpj });
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
export async function revoke(env: AppEnv, origin: string, id: string, body: { reason?: unknown; ecnpj_signature?: unknown; signed_text?: unknown }) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (row.status === "revoked") return { credential_id: id, status: "revoked", already: true };
  if (typeof body.ecnpj_signature !== "string" || typeof body.signed_text !== "string") throw new KyaError("INVALID_INPUT", "signed_text and ecnpj_signature are required");
  if (!new RegExp(`^KYA Brasil: revoke ${id}\\n`).test(body.signed_text)) throw new KyaError("INVALID_INPUT", `signed_text must start with "KYA Brasil: revoke ${id}" followed by a newline and a nonce`);
  if (row.principal_kind === "person") return revokePerson(env, row, body.signed_text, body.ecnpj_signature, typeof body.reason === "string" ? body.reason.slice(0, 200) : "revoked by the person");
  await verifyIcpSignature({ cmsBase64: body.ecnpj_signature, challenge: body.signed_text, expectedCnpj: row.cnpj, anchors: await icpAnchors(env) });
  const reason = typeof body.reason === "string" ? body.reason.slice(0, 200) : "revoked by the company";
  await store.setStatus({ id, status: "revoked", reason, actor: "company" });
  await notifyCompany(env, issuerOf(env, origin), row.cnpj, "credential.revoked", { credential_id: id, reason, actor: "company" });
  return { credential_id: id, status: "revoked", reason, revoked_at: new Date().toISOString() };
}

/**
 * Daily review of every live credential, on the two things the issuer answers for (D-15, D-16):
 *   - the e-CNPJ that authorized it: revoked at its AC → the credential is revoked (permanent), on hold
 *     → suspended; a later benign replacement of the certificate changes nothing (revocationEffect);
 *   - the company: registration no longer ATIVA → suspended; ATIVA again → reinstated.
 * ERC-8004 credentials are also suspended when the on-chain wallet changes (register again).
 * An unreachable CRL or registration source changes nothing; it is counted in `errors` and retried the next day.
 */
export async function dailyReview(env: AppEnv): Promise<{ reviewed: number; suspended: number; reinstated: number; revoked: number; errors: number; persons_purged: number }> {
  const store = new Store(env.DB);
  const issuer = (env.ISSUER_URL ?? "").replace(/\/$/, "");
  const rows = await store.dueForReview();
  let suspended = 0, reinstated = 0, revoked = 0, errors = 0;
  for (const row of rows) {
    try {
      // erc8004: a credential never outlives a wallet change on chain.
      if (row.agent_kind === "erc8004" && row.status === "active") {
        const live = await withWallet(env, { kind: "erc8004", id: row.agent_id }).catch(() => null);
        if (live && row.agent_wallet && live.wallet !== row.agent_wallet) {
          const reason = `agent wallet changed on chain (${row.agent_wallet} → ${live.wallet}); register again`;
          await store.setStatus({ id: row.id, status: "suspended", reason, actor: "cron", cause: "wallet" });
          await notifyCompany(env, issuer, row.cnpj, "credential.suspended", { credential_id: row.id, reason });
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
        await notifyCompany(env, issuer, row.cnpj, "credential.revoked", { credential_id: row.id, reason: certificateReason, actor: "issuer" });
        revoked++;
        continue;
      }
      // D-24: an unknown status (check off, sources down) changes nothing; only a confirmed one does.
      // Persons (D-29): no public registry to check; only the e-CPF's revocation above applies.
      const reg = row.principal_kind === "person" ? { legal_name: null, registration_status: "NOT_CHECKED", checked_at: null, warning: null } : await registrationOrWarning(env, row.cnpj);
      const d = principalDecision(reg.registration_status);
      const regUnknown = reg.registration_status === "UNVERIFIED" || reg.registration_status === "NOT_CHECKED";
      const hold: { cause: "certificate" | "registration"; reason: string } | null =
        certificate === "suspend" ? { cause: "certificate", reason: certificateReason ?? "e-CNPJ certificate on hold at its AC" } : !d.ok ? { cause: "registration", reason: d.reason ?? "registration not ATIVA" } : null;
      // Reinstate only what this review suspended, and only when the cause is known to be gone.
      const canLift = row.suspension_cause !== "wallet" && !(row.suspension_cause === "certificate" && certificate === "unknown") && !(row.suspension_cause === "registration" && regUnknown);
      if (row.status === "active" && hold) {
        await store.setStatus({ id: row.id, status: "suspended", reason: hold.reason, actor: "cron", cause: hold.cause, last_kyb_at: reg.checked_at ?? undefined });
        await notifyCompany(env, issuer, row.cnpj, "credential.suspended", { credential_id: row.id, reason: hold.reason });
        suspended++;
      } else if (row.status === "suspended" && !hold && canLift) {
        // Also lifts suspensions made under the old rules (sanctions, risk), which no longer apply (D-15).
        await store.setStatus({ id: row.id, status: "active", reason: null, actor: "cron", last_kyb_at: reg.checked_at ?? undefined });
        await notifyCompany(env, issuer, row.cnpj, "credential.reinstated", { credential_id: row.id });
        reinstated++;
      } else {
        await store.markReviewed(row.id, { last_kyb_at: reg.checked_at ?? undefined });
      }
    } catch (e) {
      errors++;
      console.error("review failed", row.id, e);
    }
  }
  // Retention (D-29): the keyed CPF hash and its checks go away with revoked or expired person credentials.
  const purged = await store.purgeDeadPersons().catch((e: unknown) => {
    errors++;
    console.error("person purge failed", e);
    return 0;
  });
  const summary = { reviewed: rows.length, suspended, reinstated, revoked, errors, persons_purged: purged };
  // Shown at /status (D-21): when the review last ran and what it found.
  await env.CACHE.put("status:daily_review", JSON.stringify({ ...summary, finished_at: new Date().toISOString() })).catch(() => undefined);
  return summary;
}

export { challengeText };
