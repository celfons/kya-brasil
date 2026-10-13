/**
 * The company's registration status at the Receita Federal: the one company fact the issuer acts on (D-15).
 * Sources, chosen by REGISTRATION_SOURCE:
 *   - "kyb": KYB Brasil over its internal channel (Service Binding in the cloud, KYB_URL locally);
 *   - "public": the Receita's open CNPJ data through BrasilAPI, with CNPJ.ws as fallback. The Receita itself
 *     has no free per-CNPJ API (its consultation page has a CAPTCHA), so these mirrors are the direct route;
 *   - "auto" (default): KYB when it is configured, public otherwise. A fork runs without any closed service.
 */
import { KyaError, normalizeCnpj } from "@kya-br/core";
import type { AppEnv } from "./env";
import { kybRegistration } from "./kyb";

export interface Registration {
  legal_name: string;
  registration_status: string;
  checked_at: string;
  source: "kyb" | "brasilapi" | "cnpjws";
}

export const kybConfigured = (env: AppEnv) => Boolean(env.KYB_INTERNAL_KEY && (env.KYB || env.KYB_URL));

/** Which source answers: KYB when asked for, or in auto mode when it is configured. */
export function registrationSource(env: AppEnv): "kyb" | "public" {
  const mode = env.REGISTRATION_SOURCE ?? "auto";
  if (mode === "kyb" || mode === "public") return mode;
  return kybConfigured(env) ? "kyb" : "public";
}

/** "Ativa" / "ATIVA" / "ativa " → "ATIVA" (the Receita's vocabulary: ATIVA, BAIXADA, INAPTA, SUSPENSA, NULA). */
const normalizeStatus = (s: string) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").trim().toUpperCase();

interface PublicSource {
  name: Registration["source"];
  url: (cnpj: string) => string;
  read: (body: Record<string, unknown>) => { legal_name?: unknown; status?: unknown };
}

const PUBLIC_SOURCES: PublicSource[] = [
  { name: "brasilapi", url: (c) => `https://brasilapi.com.br/api/cnpj/v1/${c}`, read: (b) => ({ legal_name: b.razao_social, status: b.descricao_situacao_cadastral }) },
  { name: "cnpjws", url: (c) => `https://publica.cnpj.ws/cnpj/${c}`, read: (b) => ({ legal_name: b.razao_social, status: (b.estabelecimento as Record<string, unknown> | undefined)?.situacao_cadastral }) }
];

async function publicRegistration(cnpj: string): Promise<Registration> {
  const failures: string[] = [];
  for (const src of PUBLIC_SOURCES) {
    try {
      const res = await fetch(src.url(cnpj), { headers: { accept: "application/json", "user-agent": "kya-brasil (+https://github.com/celfons/kya-brasil)" }, signal: AbortSignal.timeout(10_000) });
      // Not found is an answer about the CNPJ, not a source failure: stop here.
      if (res.status === 404) throw new KyaError("NOT_FOUND", "CNPJ not found at the Receita Federal");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const { legal_name, status } = src.read((await res.json()) as Record<string, unknown>);
      if (typeof legal_name !== "string" || typeof status !== "string" || !status.trim()) throw new Error("answer without razao_social or situacao_cadastral");
      return { legal_name, registration_status: normalizeStatus(status), checked_at: new Date().toISOString(), source: src.name };
    } catch (e) {
      if (e instanceof KyaError) throw e;
      failures.push(`${src.name}: ${(e as Error).message}`);
    }
  }
  throw new KyaError("REGISTRY_UNAVAILABLE", `no source answered for the registration status (${failures.join("; ")})`);
}

export async function companyRegistration(env: AppEnv, cnpj: string): Promise<Registration> {
  const c = normalizeCnpj(cnpj);
  if (registrationSource(env) === "kyb") {
    const r = await kybRegistration(env, c);
    return { ...r, registration_status: normalizeStatus(r.registration_status), source: "kyb" };
  }
  return publicRegistration(c);
}
