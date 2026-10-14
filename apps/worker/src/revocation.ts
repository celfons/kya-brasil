/**
 * Fetches the CRL (LCR) of an e-CNPJ certificate and checks its serial (D-16). The distribution points
 * are tried in the order the certificate lists them; a CRL is cached in KV until its nextUpdate (capped
 * at 6 hours) and kept verified and indexed in memory for up to an hour, so the daily review downloads,
 * verifies and parses each AC's CRL once.
 */
import { KyaError, type RevocationStatus, type VerifiedCrl, verifyCrl } from "@kya-brasil/core";
import type { AppEnv } from "./env";

const KV_MAX_BYTES = 25 * 1024 * 1024; // KV value limit; larger CRLs are downloaded on every miss
const MAX_TTL_S = 6 * 3600;
const MEMORY_TTL_MS = 3600_000;

/** Verified CRLs by URL and AC certificate: one download, one signature check, one parse per hour. */
const memory = new Map<string, { crl: VerifiedCrl; at: number }>();

async function download(env: AppEnv, url: string): Promise<{ der: ArrayBuffer; fresh: boolean }> {
  const cached = await env.CACHE.get(`crl:${url}`, "arrayBuffer");
  if (cached) return { der: cached, fresh: false };
  const res = await fetch(url, { headers: { accept: "application/pkix-crl, application/octet-stream" }, signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return { der: await res.arrayBuffer(), fresh: true };
}

async function crlFor(env: AppEnv, url: string, issuerCertificate: string): Promise<VerifiedCrl> {
  const key = `${url}\n${issuerCertificate}`;
  const hit = memory.get(key);
  if (hit && Date.now() - hit.at < MEMORY_TTL_MS && (!hit.crl.next_update || Date.parse(hit.crl.next_update) > Date.now())) return hit.crl;
  const { der, fresh } = await download(env, url);
  const crl = await verifyCrl({ crlDer: der, issuerCertificate });
  memory.set(key, { crl, at: Date.now() });
  if (fresh && der.byteLength <= KV_MAX_BYTES) {
    const untilNext = crl.next_update ? Math.floor((Date.parse(crl.next_update) - Date.now()) / 1000) : MAX_TTL_S;
    const ttl = Math.min(MAX_TTL_S, untilNext);
    if (ttl >= 60) await env.CACHE.put(`crl:${url}`, der, { expirationTtl: ttl }).catch(() => undefined);
  }
  return crl;
}

/** Revocation status from the first distribution point that yields a trustworthy CRL; REVOCATION_UNAVAILABLE otherwise. */
export async function certificateRevocation(env: AppEnv, cert: { serial_number: string; crl_urls: string[]; issuer_certificate: string | null }): Promise<RevocationStatus> {
  if (!cert.issuer_certificate) throw new KyaError("REVOCATION_UNAVAILABLE", "the AC that issued the e-CNPJ is not among the ICP-Brasil anchors; its CRL cannot be verified");
  if (!cert.crl_urls.length) throw new KyaError("REVOCATION_UNAVAILABLE", "the e-CNPJ certificate names no HTTP CRL distribution point");
  const failures: string[] = [];
  for (const url of cert.crl_urls) {
    try {
      return (await crlFor(env, url, cert.issuer_certificate)).lookup(cert.serial_number);
    } catch (e) {
      failures.push(`${url}: ${(e as Error).message}`);
    }
  }
  throw new KyaError("REVOCATION_UNAVAILABLE", `could not check the e-CNPJ CRL (${failures.join("; ")})`);
}

export function resetCrlMemory() {
  memory.clear();
}
