/**
 * ICP-Brasil trust anchors (root certificates of the AC Raiz, versions in force). In the cloud they
 * live in KV under `icp:anchors` as a PEM bundle, uploaded by scripts/icp-anchors.mjs from the ITI
 * repository (https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz). Locally the
 * ICP_ANCHORS_PEM var can carry the same bundle. No anchors = no issuance (fail closed).
 */
import type { AppEnv } from "./env";

let cached: { at: number; anchors: string[] } | null = null;

export async function icpAnchors(env: AppEnv): Promise<string[]> {
  if (cached && Date.now() - cached.at < 3600_000) return cached.anchors;
  const pem = (await env.CACHE.get("icp:anchors")) ?? env.ICP_ANCHORS_PEM ?? "";
  const anchors = [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) => m[1]!.replace(/\s+/g, ""));
  cached = { at: Date.now(), anchors };
  return anchors;
}

export function resetAnchorsCache() {
  cached = null;
}
