/**
 * What a company sees and hears about the agents that act in its name (D-20), both authorized by its e-CNPJ:
 *   - inventory: every credential ever registered for its CNPJ, whoever held the certificate (an accountant,
 *     another employee), so nothing acts in its name unseen;
 *   - webhook: one https URL that receives signed events (issued, renewed, suspended, reinstated, revoked),
 *     so an agent credentialed in its name, or one that stopped working, is noticed, not discovered later.
 * Requests are e-CNPJ-signed texts with an `at:` timestamp: accepted within 10 minutes, and for the webhook
 * only if newer than the last accepted one, so a captured request cannot be replayed.
 */
import { KyaError, formatCnpj, isValidCnpj, normalizeCnpj, verifyIcpSignature } from "@kya-brasil/core";
import { icpAnchors } from "./anchors";
import { signAnswer } from "./attest";
import type { AppEnv } from "./env";
import { certificateRevocation } from "./revocation";
import { Store } from "./store";

const MAX_SKEW_MS = 10 * 60_000;
const WEBHOOK_TIMEOUT_MS = 5_000;

export type CompanyEvent = "credential.issued" | "credential.renewed" | "credential.suspended" | "credential.reinstated" | "credential.revoked";

/** The exact text a company signs: `KYA Brasil: <verb> <cnpj>`, optional extra lines, then `at: <ISO time>`. */
export function companyText(verb: "agents" | "webhook", cnpj: string, at: string, extra: string[] = []): string {
  return [`KYA Brasil: ${verb} ${normalizeCnpj(cnpj)}`, ...extra, `at: ${at}`].join("\n");
}

/** Verifies an e-CNPJ-signed company request and returns its lines and timestamp. */
async function companyRequest(env: AppEnv, verb: "agents" | "webhook", cnpjParam: string, body: { signed_text?: unknown; ecnpj_signature?: unknown }) {
  if (!isValidCnpj(cnpjParam)) throw new KyaError("INVALID_CNPJ", "cnpj must be a valid Brazilian CNPJ");
  const cnpj = normalizeCnpj(cnpjParam);
  if (typeof body.signed_text !== "string" || typeof body.ecnpj_signature !== "string") throw new KyaError("INVALID_INPUT", "signed_text and ecnpj_signature are required");
  const lines = body.signed_text.split("\n");
  if (lines[0] !== `KYA Brasil: ${verb} ${cnpj}`) throw new KyaError("INVALID_INPUT", `signed_text must start with "KYA Brasil: ${verb} ${cnpj}"`);
  const atLine = lines.at(-1) ?? "";
  const at = atLine.startsWith("at: ") ? Date.parse(atLine.slice(4)) : Number.NaN;
  if (!Number.isFinite(at) || Math.abs(Date.now() - at) > MAX_SKEW_MS) throw new KyaError("INVALID_INPUT", 'signed_text must end with "at: <ISO time>" within 10 minutes of now');
  const icp = await verifyIcpSignature({ cmsBase64: body.ecnpj_signature, challenge: body.signed_text, expectedCnpj: cnpj, anchors: await icpAnchors(env) });
  const revocation = await certificateRevocation(env, icp);
  if (revocation.revoked) throw new KyaError("CERTIFICATE_REVOKED", `the e-CNPJ certificate was revoked by its AC on ${revocation.revoked_at}`);
  return { cnpj, lines, at: new Date(at).toISOString() };
}

/** Inventory: every credential registered for the CNPJ, any status (free, e-CNPJ-signed). */
export async function companyAgents(env: AppEnv, cnpjParam: string, body: { signed_text?: unknown; ecnpj_signature?: unknown }) {
  const { cnpj } = await companyRequest(env, "agents", cnpjParam, body);
  const rows = await new Store(env.DB).byCnpj(cnpj);
  return {
    cnpj,
    cnpj_formatted: formatCnpj(cnpj),
    count: rows.length,
    agents: rows.map((r) => ({
      credential_id: r.id,
      agent: { kind: r.agent_kind, id: r.agent_id, ...(r.agent_wallet ? { wallet: r.agent_wallet } : {}) },
      status: r.status,
      status_reason: r.status_reason,
      mandate: JSON.parse(r.mandate) as unknown,
      certificate_sha256: r.certificate_sha256,
      created_at: r.created_at,
      issued_at: r.issued_at,
      expires_at: r.expires_at
    }))
  };
}

function validWebhookUrl(raw: string): string | null {
  if (raw === "-") return null;
  if (raw.length > 512 || !URL.canParse(raw)) throw new KyaError("INVALID_INPUT", "url must be an https URL up to 512 chars, or - to remove the webhook");
  const u = new URL(raw);
  const ipLiteral = /^[\d.]+$/.test(u.hostname) || u.hostname.includes(":");
  if (u.protocol !== "https:" || u.username || u.password || ipLiteral || u.hostname === "localhost") throw new KyaError("INVALID_INPUT", "url must be https on a public host name, without credentials");
  return u.toString();
}

/** Sets (or removes, with url "-") the company's webhook. signed_text: "KYA Brasil: webhook <cnpj>\nurl: <url|->\nat: <ISO>". */
export async function setCompanyWebhook(env: AppEnv, cnpjParam: string, body: { signed_text?: unknown; ecnpj_signature?: unknown }) {
  const { cnpj, lines, at } = await companyRequest(env, "webhook", cnpjParam, body);
  const urlLine = lines.find((l) => l.startsWith("url: "));
  if (!urlLine || lines.length !== 3) throw new KyaError("INVALID_INPUT", 'signed_text must be "KYA Brasil: webhook <cnpj>", "url: <https url or ->", "at: <ISO time>"');
  const url = validWebhookUrl(urlLine.slice(5));
  const store = new Store(env.DB);
  const current = await store.webhook(cnpj);
  if (current && Date.parse(at) <= Date.parse(current.signed_at)) throw new KyaError("CONFLICT", "a newer webhook request was already accepted; sign a new one");
  await store.setWebhook(cnpj, url, at);
  return { cnpj, webhook: url, signed_at: at, events: ["credential.issued", "credential.renewed", "credential.suspended", "credential.reinstated", "credential.revoked"] };
}

/**
 * Sends a signed event to the company's webhook, if it has one. Best effort: one POST with a 5 s timeout,
 * failures are logged and never break the operation that caused the event.
 */
export async function notifyCompany(env: AppEnv, issuer: string, cnpj: string, event: CompanyEvent, data: Record<string, unknown>): Promise<void> {
  try {
    const hook = await new Store(env.DB).webhook(cnpj);
    if (!hook?.url) return;
    const out: Record<string, unknown> = { event, cnpj, at: new Date().toISOString(), data };
    const attestation = await signAnswer(env, out, issuer);
    await fetch(hook.url, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "kya-brasil-webhook" },
      body: JSON.stringify(attestation ? { ...out, attestation } : out),
      signal: AbortSignal.timeout(WEBHOOK_TIMEOUT_MS)
    });
  } catch (e) {
    console.error("webhook delivery failed", cnpj, event, e);
  }
}
