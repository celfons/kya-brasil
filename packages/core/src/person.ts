/**
 * Natural persons as principals (D-29): "this agent key acts for a person who signed with an ICP-Brasil e-CPF".
 * Privacy rules: the name is never stored or published; the CPF is never stored, published or revealed. The
 * issuer keeps only HMAC(key, CPF) while a credential is alive, answers paying verifiers whether a CPF they
 * already know matches, and gives each verifier its own pseudonymous subject reference for that person.
 */
import { KyaError, type AgentKey } from "./types.js";
import { CHALLENGE_TTL_SECONDS, type Challenge } from "./challenge.js";

/** 11 digits; throws INVALID_INPUT on anything that is not a valid CPF (check digits included). */
export function normalizeCpf(input: string): string {
  const d = String(input).replace(/\D/g, "");
  if (!isValidCpf(d)) throw new KyaError("INVALID_INPUT", "cpf must be a valid Brazilian CPF");
  return d;
}

export function isValidCpf(input: string): boolean {
  const d = String(input).replace(/\D/g, "");
  if (d.length !== 11 || /^(\d)\1{10}$/.test(d)) return false;
  const check = (len: number) => {
    let sum = 0;
    for (let i = 0; i < len; i++) sum += Number(d[i]) * (len + 1 - i);
    const r = (sum * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return check(9) === Number(d[9]) && check(10) === Number(d[10]);
}

const b64url = (u: Uint8Array) => {
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function hmac(keyB64: string, message: string): Promise<string> {
  const raw = unb64(keyB64);
  if (raw.length < 32) throw new KyaError("UPSTREAM_ERROR", "person key must be at least 32 bytes");
  const key = await crypto.subtle.importKey("raw", raw.buffer as ArrayBuffer, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message))));
}

/** Keyed hash of a CPF: what the issuer stores. Without the key, a CPF cannot be tested against it. */
export const personHash = (keyB64: string, cpf: string) => hmac(keyB64, `kya:cpf:${normalizeCpf(cpf)}`);

/**
 * Pairwise subject reference: the same person gets a different, stable value for each verifier, so a verifier
 * can track that person's agents on its side without two verifiers being able to link them.
 */
export const subjectRef = (keyB64: string, hash: string, verifier: string) => hmac(keyB64, `kya:subject:${hash}:${verifier.toLowerCase()}`);

/** Versioned keys from a JSON object {"1": "<base64 32 bytes>", "2": ...}; the highest version is current. */
export function personKeys(json: string | undefined): { current: { version: number; key: string }; all: Map<number, string> } | null {
  if (!json) return null;
  let parsed: Record<string, string>;
  try {
    parsed = JSON.parse(json) as Record<string, string>;
  } catch {
    throw new KyaError("UPSTREAM_ERROR", "PERSON_HMAC_KEYS is not valid JSON");
  }
  const all = new Map(Object.entries(parsed).map(([v, k]) => [Number(v), k] as [number, string]).filter(([v, k]) => Number.isInteger(v) && v > 0 && typeof k === "string"));
  if (!all.size) return null;
  const version = Math.max(...all.keys());
  return { current: { version, key: all.get(version)! }, all };
}

/** Consent the person signs with the e-CPF; part of the challenge text, so the signature records it. */
export const PERSON_CONSENT =
  "I authorize this issuer to keep a keyed hash of my CPF while this credential is valid and to answer, to verifiers who pay for each check, only whether a CPF they already have matches. My name and CPF are never stored in clear, published or revealed. / Autorizo este emissor a guardar um hash com chave do meu CPF enquanto esta credencial valer e a responder, a verificadores que pagam por consulta, apenas se um CPF que eles ja tem confere. Meu nome e meu CPF nunca sao guardados em claro, publicados ou revelados.";

/** The text a person and the agent sign (no CPF: it comes from the e-CPF certificate). */
export function personChallengeText(p: { issuer: string; challenge_id: string; agent: AgentKey; expires_at: string }): string {
  return [
    "KYA Brasil: prove this agent key acts for me, a natural person",
    `issuer: ${p.issuer}`,
    `challenge: ${p.challenge_id}`,
    `agent: ${p.agent.kind}:${p.agent.id}`,
    "principal: person (e-CPF)",
    `consent: ${PERSON_CONSENT}`,
    `expires: ${p.expires_at}`
  ].join("\n");
}

/** The text a person signs with the e-CPF to see their own agents (accepted for 10 minutes after `at`). */
export const personAgentsText = (at: Date = new Date()) => `KYA Brasil: my agents\nat: ${at.toISOString()}`;

export function newPersonChallenge(p: { issuer: string; agent: AgentKey; now?: Date }): Challenge {
  const now = p.now ?? new Date();
  const challenge_id = crypto.randomUUID();
  const expires_at = new Date(now.getTime() + CHALLENGE_TTL_SECONDS * 1000).toISOString();
  return { challenge_id, expires_at, text: personChallengeText({ issuer: p.issuer, challenge_id, agent: p.agent, expires_at }) };
}
