/**
 * KYB Brasil client. In the cloud the KYB Worker is a Service Binding (direct Worker-to-Worker
 * call, no public HTTP, no x402); locally KYB_URL points at a `wrangler dev` of KYB. Either way
 * the call goes to KYB's internal channel (/internal/v1/<tool>) with the shared key, so it is
 * never billed per call: the credential price covers it.
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

export async function kybRiskScreen(env: AppEnv, cnpj: string): Promise<{ snapshot: KybSnapshot; legal_name: string; warnings: string[] }> {
  const c = normalizeCnpj(cnpj);
  const key = env.KYB_INTERNAL_KEY;
  if (!key) throw new KyaError("KYB_UNAVAILABLE", "KYB channel not configured (KYB_INTERNAL_KEY)");
  const path = `/internal/v1/br_risk_screen?cnpj=${encodeURIComponent(c)}`;
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
  const r = (await res.json()) as RiskScreen;
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
