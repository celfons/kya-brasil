import { type Attestation, importPrivateKey, keyIdOf, publicJwkFromPrivate, signAttestation, verifyAttestation } from "@kya-br/core";
import type { AppEnv } from "./env";

let cache: { key: CryptoKey; jwk: JsonWebKey; keyId: string } | null | undefined;
let previous: { keyId: string; jwk: JsonWebKey; retired_at: string }[] | undefined;

export async function material(env: AppEnv) {
  if (cache !== undefined) return cache;
  if (!env.ATTEST_PRIVATE_KEY) return (cache = null);
  try {
    const key = await importPrivateKey(env.ATTEST_PRIVATE_KEY);
    const jwk = await publicJwkFromPrivate(env.ATTEST_PRIVATE_KEY);
    cache = { key, jwk, keyId: await keyIdOf(jwk) };
  } catch (e) {
    console.error("attestation key unusable", e);
    cache = null;
  }
  return cache;
}

async function previousKeys(env: AppEnv) {
  if (previous !== undefined) return previous;
  previous = [];
  if (!env.ATTEST_PREVIOUS_KEYS) return previous;
  try {
    const list = JSON.parse(env.ATTEST_PREVIOUS_KEYS) as { jwk?: JsonWebKey; retired_at?: string }[];
    for (const k of Array.isArray(list) ? list : []) {
      if (!k?.jwk || k.jwk.kty !== "OKP" || k.jwk.crv !== "Ed25519" || typeof k.jwk.x !== "string") continue;
      previous.push({ keyId: await keyIdOf(k.jwk), jwk: k.jwk, retired_at: String(k.retired_at ?? "") });
    }
  } catch (e) {
    console.error("ATTEST_PREVIOUS_KEYS unusable", e);
  }
  return previous;
}

export async function publishedKeys(env: AppEnv) {
  const m = await material(env);
  const prev = await previousKeys(env);
  return [...(m ? [{ key_id: m.keyId, jwk: m.jwk, status: "active" as const }] : []), ...prev.map((k) => ({ key_id: k.keyId, jwk: k.jwk, status: "retired" as const, retired_at: k.retired_at }))];
}

/** Signs any answer (used for check_action verdicts and the paid verification receipt). */
export async function signAnswer(env: AppEnv, answer: Record<string, unknown>, origin: string): Promise<Attestation | null> {
  const m = await material(env);
  if (!m) return null;
  try {
    return await signAttestation(answer, m.key, m.keyId, `${origin}/v1/verify`);
  } catch (e) {
    console.error("attestation failed", e);
    return null;
  }
}

export async function verifyAnswer(env: AppEnv, answer: Record<string, unknown>) {
  const keys = await publishedKeys(env);
  if (!keys.length) return { valid: false, reason: "this deployment has no attestation key" };
  const att = answer.attestation as { key_id?: string } | undefined;
  const key = keys.find((k) => k.key_id === att?.key_id) ?? keys[0]!;
  const result = await verifyAttestation(answer, key.jwk);
  return key.status === "retired" && result.valid ? { ...result, key_status: "retired" as const, retired_at: key.retired_at } : result;
}

export function resetAttestationCache() {
  cache = undefined;
  previous = undefined;
}
