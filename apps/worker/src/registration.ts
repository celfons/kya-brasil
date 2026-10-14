/**
 * The company's registration status at the Receita Federal: the one company fact the issuer acts on (D-15).
 * The Receita has no free per-CNPJ API (its consultation page has a CAPTCHA), so the status comes from its
 * open CNPJ data through public mirrors, tried in order (D-23):
 *   1. CNPJ_API_URL, when set: any service answering in the BrasilAPI format, e.g. a self-hosted BrasilAPI
 *      (open source) or your own import of the Receita's monthly open-data dump; "{cnpj}" is replaced;
 *   2. BrasilAPI (brasilapi.com.br, open source, no key);
 *   3. CNPJ.ws public API (no key).
 * No key, no contract, no closed service: anyone running the issuer gets the same answer.
 */
import { KyaError, normalizeCnpj } from "@kya-brasil/core";
import type { AppEnv } from "./env";

export interface Registration {
  legal_name: string;
  registration_status: string;
  checked_at: string;
  source: "custom" | "brasilapi" | "cnpjws";
}

/** "Ativa" / "ATIVA" / "ativa " → "ATIVA" (the Receita's vocabulary: ATIVA, BAIXADA, INAPTA, SUSPENSA, NULA). */
const normalizeStatus = (s: string) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").trim().toUpperCase();

interface PublicSource {
  name: Registration["source"];
  url: (cnpj: string) => string;
  read: (body: Record<string, unknown>) => { legal_name?: unknown; status?: unknown };
}

const brasilApiShape = (b: Record<string, unknown>) => ({ legal_name: b.razao_social, status: b.descricao_situacao_cadastral });

const PUBLIC_SOURCES: PublicSource[] = [
  { name: "brasilapi", url: (c) => `https://brasilapi.com.br/api/cnpj/v1/${c}`, read: brasilApiShape },
  { name: "cnpjws", url: (c) => `https://publica.cnpj.ws/cnpj/${c}`, read: (b) => ({ legal_name: b.razao_social, status: (b.estabelecimento as Record<string, unknown> | undefined)?.situacao_cadastral }) }
];

/** The sources this deployment uses, in order (also shown at /status). */
export function registrationSources(env: AppEnv): PublicSource[] {
  const custom = env.CNPJ_API_URL?.trim();
  if (!custom) return PUBLIC_SOURCES;
  if (!/^https?:\/\//.test(custom) || !custom.includes("{cnpj}")) throw new KyaError("UPSTREAM_ERROR", "CNPJ_API_URL must be an http(s) URL containing {cnpj}");
  return [{ name: "custom", url: (c) => custom.replace("{cnpj}", c), read: brasilApiShape }, ...PUBLIC_SOURCES];
}

/** Whether this issuer checks the registration status at all (REGISTRATION_CHECK, default on; D-24). */
export const registrationCheckEnabled = (env: AppEnv) => (env.REGISTRATION_CHECK ?? "on").trim().toLowerCase() !== "off";

export interface RegistrationOutcome {
  /** null when unknown: use the name in the e-CNPJ certificate. */
  legal_name: string | null;
  /** ATIVA, BAIXADA, ... from the Receita, or UNVERIFIED (no source answered) / NOT_CHECKED (check off). */
  registration_status: string;
  checked_at: string | null;
  warning: string | null;
}

/**
 * D-24: the registration check never blocks the service. Off, or with every source down, the status is
 * UNVERIFIED / NOT_CHECKED with a warning; only a confirmed status other than ATIVA refuses issuance.
 */
export async function registrationOrWarning(env: AppEnv, cnpj: string): Promise<RegistrationOutcome> {
  if (!registrationCheckEnabled(env)) {
    return { legal_name: null, registration_status: "NOT_CHECKED", checked_at: null, warning: "registration status not checked: the check is off on this issuer (REGISTRATION_CHECK=off)" };
  }
  try {
    const r = await companyRegistration(env, cnpj);
    return { legal_name: r.legal_name, registration_status: r.registration_status, checked_at: r.checked_at, warning: null };
  } catch (e) {
    const why = e instanceof KyaError && e.code === "NOT_FOUND" ? "CNPJ not found in the open-data source" : (e as Error).message;
    return { legal_name: null, registration_status: "UNVERIFIED", checked_at: null, warning: `registration status could not be confirmed (${why}); the daily review checks it again` };
  }
}

export async function companyRegistration(env: AppEnv, cnpj: string): Promise<Registration> {
  const c = normalizeCnpj(cnpj);
  const failures: string[] = [];
  for (const src of registrationSources(env)) {
    try {
      const res = await fetch(src.url(c), { headers: { accept: "application/json", "user-agent": "kya-brasil (+https://github.com/celfons/kya-brasil)" }, signal: AbortSignal.timeout(10_000) });
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
