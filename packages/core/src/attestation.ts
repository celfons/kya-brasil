/**
 * Signed attestation of an answer: "this service returned exactly this JSON at this time".
 * Ed25519 over the SHA-256 of the canonical JSON (keys sorted, no whitespace) of the answer
 * without `attestation` and `receipt`. WebCrypto only, so it runs on Workers and Node alike.
 */
import type { Attestation } from "./types";

export function canonicalize(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(o[k])}`).join(",")}}`;
}

export function attestedPayload(answer: Record<string, unknown>): Record<string, unknown> {
  const { attestation: _a, receipt: _r, ...rest } = answer;
  return rest;
}

const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sha256(text: string): Promise<{ hex: string; bytes: Uint8Array }> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return { hex: hex(digest), bytes: new Uint8Array(digest) };
}

/** New Ed25519 key pair: private as PKCS#8 base64 (store as a secret), public as JWK (publish). */
export async function generateAttestationKey(): Promise<{ privateKeyPkcs8: string; publicJwk: JsonWebKey; keyId: string }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pkcs8 = (await crypto.subtle.exportKey("pkcs8", kp.privateKey)) as ArrayBuffer;
  const jwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JsonWebKey;
  return { privateKeyPkcs8: b64(pkcs8), publicJwk: jwk, keyId: await keyIdOf(jwk) };
}

/** key_id = first 16 hex chars of SHA-256 of the raw public key. */
export async function keyIdOf(publicJwk: JsonWebKey): Promise<string> {
  return (await sha256(publicJwk.x ?? "")).hex.slice(0, 16);
}

export async function importPrivateKey(pkcs8Base64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", unb64(pkcs8Base64), { name: "Ed25519" }, true, ["sign"]);
}

export async function publicJwkFromPrivate(pkcs8Base64: string): Promise<JsonWebKey> {
  const priv = await crypto.subtle.importKey("pkcs8", unb64(pkcs8Base64), { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", priv)) as JsonWebKey;
  const { d: _d, ...pub } = jwk; // drop the private part
  return { ...pub, key_ops: ["verify"] };
}

export async function signAttestation(answer: Record<string, unknown>, privateKey: CryptoKey, keyId: string, verifyUrl: string, now = new Date()): Promise<Attestation> {
  const payload = attestedPayload(answer);
  const { hex: digestHex, bytes } = await sha256(canonicalize(payload));
  const signed_at = now.toISOString();
  const message = new TextEncoder().encode(`${digestHex}\n${signed_at}`);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, message);
  void bytes;
  return { algorithm: "ed25519", key_id: keyId, sha256: digestHex, signed_at, signature: b64(sig), verify_url: verifyUrl };
}

/** Recomputes the hash from the answer and checks the signature with the public key. */
export async function verifyAttestation(answer: Record<string, unknown>, publicJwk: JsonWebKey): Promise<{ valid: boolean; reason?: string; key_id?: string; signed_at?: string }> {
  const att = answer.attestation as Attestation | undefined;
  if (!att || att.algorithm !== "ed25519") return { valid: false, reason: "no ed25519 attestation in the answer" };
  const { hex: digestHex } = await sha256(canonicalize(attestedPayload(answer)));
  if (digestHex !== att.sha256) return { valid: false, reason: "content hash mismatch: the answer was modified", key_id: att.key_id, signed_at: att.signed_at };
  const keyId = await keyIdOf(publicJwk);
  if (keyId !== att.key_id) return { valid: false, reason: `signed with key ${att.key_id}, verifying with ${keyId}`, key_id: att.key_id, signed_at: att.signed_at };
  const key = await crypto.subtle.importKey("jwk", publicJwk, { name: "Ed25519" }, true, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, unb64(att.signature), new TextEncoder().encode(`${digestHex}\n${att.signed_at}`));
  return ok ? { valid: true, key_id: att.key_id, signed_at: att.signed_at } : { valid: false, reason: "signature does not verify", key_id: att.key_id, signed_at: att.signed_at };
}
