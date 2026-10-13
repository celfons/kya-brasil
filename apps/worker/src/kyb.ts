/**
 * KYB Brasil client. In the cloud the KYB Worker is a Service Binding (direct Worker-to-Worker
 * call, no public HTTP, no x402); locally KYB_URL points at a `wrangler dev` of KYB. Either way
 * the call goes to KYB's internal channel (/internal/v1/<tool>) with the shared key, so it is
 * never billed per call: the credential price covers it.
 *
 * Since D-15 only the registration status decides anything (issuance, suspension); the risk screen at
 * issuance only fills the informative `kyb_snapshot` that /v1 credentials keep carrying.
 */
import { type KybSnapshot, KyaError, normalizeCnpj } from "@kya-br/core";
import type { AppEnv } from "./env";

interface RiskScreen {
  company: { legal_name: string; registration_status: string };
  sanctions: { active_hits: number; hits?: { list: string; active: boolean; sanctioned_entity?: { relation: string } }[] } | null;
  federal_debt: { total_brl: number; inscriptions: number } | null;
  environmental_embargoes: { active: number } | null;
  risk: { level: KybSnapshot["risk_level"]; score: number; red_flags: { code: string }[] };
  warnings: string[];
}

async function kybTool<T>(env: AppEnv, tool: "br_risk_screen" | "br_company_check", cnpj: string): Promise<T> {
  const c = normalizeCnpj(cnpj);
  const key = env.KYB_INTERNAL_KEY;
  if (!key) throw new KyaError("KYB_UNAVAILABLE", "KYB channel not configured (KYB_INTERNAL_KEY)");
  const path = `/internal/v1/${tool}?cnpj=${encodeURIComponent(c)}`;
  const req = new Request(`${env.KYB ? "https://kyb.internal" : (env.KYB_URL ?? "").replace(/\/$/, "")}${path}`, { headers: { "x-internal-key": key, accept: "application/json" } });
  let res: Response;
  try {
    res = env.KYB ? await env.KYB.fetch(req) : await fetch(req);
  } catch (e) {
    throw new KyaError("KYB_UNAVAILABLE", `KYB call failed: ${(e as Error).message}`);
  }
  if (res.status === 400) throw new KyaError("INVALID_CNPJ", `KYB rejected the CNPJ: ${await res.text()}`);
  if (res.status === 404) throw new KyaError("NOT_FOUND", "CNPJ not found at the Receita Federal");
  if (!res.ok) throw new KyaError("KYB_UNAVAILABLE", `KYB answered HTTP ${res.status}`);
  return (await res.json()) as T;
}

/** Registration status at the Receita Federal: the only KYB fact the issuer acts on (D-15). Free tool, used by the daily review. */
export async function kybRegistration(env: AppEnv, cnpj: string): Promise<{ legal_name: string; registration_status: string; checked_at: string }> {
  const r = await kybTool<{ legal_name: string; registration_status: string }>(env, "br_company_check", cnpj);
  return { legal_name: r.legal_name, registration_status: r.registration_status, checked_at: new Date().toISOString() };
}

/** Risk screen at issuance: registration status plus the informative snapshot carried in the credential. */
export async function kybRiskScreen(env: AppEnv, cnpj: string): Promise<{ snapshot: KybSnapshot; legal_name: string; warnings: string[] }> {
  const r = await kybTool<RiskScreen>(env, "br_risk_screen", cnpj);
  const forced = (r.risk.red_flags ?? []).some((f) => f.code === "FORCED_LABOR_LIST") || (r.sanctions?.hits ?? []).some((h) => h.list === "TRABALHO_ESCRAVO" && h.active);
  const snapshot: KybSnapshot = {
    risk_level: r.risk.level,
    risk_score: r.risk.score,
    registration_status: r.company.registration_status,
    active_sanctions: r.sanctions?.active_hits ?? 0,
    forced_labor: forced,
    federal_debt_brl: r.federal_debt ? r.federal_debt.total_brl : null,
    active_embargoes: r.environmental_embargoes?.active ?? 0,
    red_flags: (r.risk.red_flags ?? []).map((f) => f.code),
    checked_at: new Date().toISOString()
  };
  return { snapshot, legal_name: r.company.legal_name, warnings: r.warnings ?? [] };
}
