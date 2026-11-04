/**
 * Credential assembly, signing and verification. The signature is an Ed25519 attestation over the
 * SHA-256 of the canonical JSON without `attestation`, so the public key document at
 * /.well-known/kya.json and the SDK's verifyAttestation() verify credentials and verdicts alike.
 */
import { attestedPayload, canonicalize, signAttestation, verifyAttestation } from "./attestation.js";
import { formatCnpj, normalizeCnpj } from "./cnpj.js";
import { type Credential, type CredentialStatus, type KybSnapshot, type Mandate, type AgentKey, KyaError } from "./types.js";

/**
 * D-35: when a credential expires. The lifetime is the caller's (`ttl_seconds`, no default: it is a risk decision),
 * and the credential never outlives the mandate nor the certificate that signed it, so a proof checked against
 * ICP-Brasil (D-34) never fails while the credential still reads as active.
 */
export function credentialExpiry(p: { now: Date; ttl_seconds: number; mandate: Pick<Mandate, "valid_until">; certificate_not_after: string }): Date {
  if (typeof p.ttl_seconds !== "number" || !Number.isFinite(p.ttl_seconds) || p.ttl_seconds <= 0) throw new KyaError("INVALID_INPUT", "ttl_seconds must be a positive number of seconds (the credential lifetime is the caller's decision)");
  const notAfter = new Date(p.certificate_not_after);
  if (Number.isNaN(notAfter.getTime())) throw new KyaError("INVALID_INPUT", "certificate.not_after must be an ISO 8601 date");
  if (notAfter <= p.now) throw new KyaError("CERTIFICATE_INVALID", `certificate expired on ${notAfter.toISOString()}`);
  const candidates = [new Date(p.now.getTime() + p.ttl_seconds * 1000), notAfter];
  if (p.mandate.valid_until) candidates.push(new Date(p.mandate.valid_until));
  return new Date(Math.min(...candidates.map((d) => d.getTime())));
}

export function buildCredential(p: {
  credential_id: string;
  agent: AgentKey;
  cnpj: string;
  legal_name: string;
  registration_status: string;
  /** not_after: the signing certificate's end of validity (IcpProof.not_after); the credential never outlives it. */
  certificate: { sha256: string; subject: string; issuer: string; signed_at: string; not_after: string };
  mandate: Mandate;
  /** D-35: the credential lifetime in seconds. Required, no default: how long a credential lives is the caller's risk. */
  ttl_seconds: number;
  /** D-33: the mandate SHA-256 the signed challenge carried (mandateSha256OfChallenge). */
  mandate_sha256?: string;
  /** /v1 compatibility only; leave out (null). */
  kyb?: KybSnapshot | null;
  issuer: string;
  now?: Date;
  status?: CredentialStatus;
  status_reason?: string | null;
}): Credential {
  const now = p.now ?? new Date();
  const cnpj = normalizeCnpj(p.cnpj);
  const expires = credentialExpiry({ now, ttl_seconds: p.ttl_seconds, mandate: p.mandate, certificate_not_after: p.certificate.not_after });
  return {
    credential_id: p.credential_id,
    version: 1,
    agent: p.agent,
    principal: { cnpj, cnpj_formatted: formatCnpj(cnpj), legal_name: p.legal_name, registration_status: p.registration_status },
    authorized_by: { method: "icp-brasil-e-cnpj", certificate_sha256: p.certificate.sha256, certificate_subject: p.certificate.subject, issuer: p.certificate.issuer, signed_at: p.certificate.signed_at, ...(p.mandate_sha256 ? { mandate_sha256: p.mandate_sha256 } : {}) },
    mandate: p.mandate,
    kyb_snapshot: p.kyb ?? null,
    status: p.status ?? "active",
    status_reason: p.status_reason ?? null,
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    issuer: p.issuer,
    verify_url: `${p.issuer}/v1/agents/${p.credential_id}`,
    revocation_url: `${p.issuer}/v1/agents/${p.credential_id}/status`
  };
}

/** D-29: credential of a natural person. Nothing personal: no name, no CPF, no certificate subject. */
export function buildPersonCredential(p: {
  credential_id: string;
  agent: AgentKey;
  /** not_after: the signing certificate's end of validity (IcpPersonProof.not_after); the credential never outlives it. */
  certificate: { sha256: string; issuer: string; signed_at: string; not_after: string };
  mandate: Mandate;
  /** D-35: the credential lifetime in seconds. Required, no default. */
  ttl_seconds: number;
  /** D-33: the mandate SHA-256 the signed challenge carried (mandateSha256OfChallenge). */
  mandate_sha256?: string;
  issuer: string;
  now?: Date;
}): Credential {
  const now = p.now ?? new Date();
  const expires = credentialExpiry({ now, ttl_seconds: p.ttl_seconds, mandate: p.mandate, certificate_not_after: p.certificate.not_after });
  return {
    credential_id: p.credential_id,
    version: 1,
    agent: p.agent,
    principal: { kind: "person", verified_by: "icp-brasil-e-cpf" },
    authorized_by: { method: "icp-brasil-e-cpf", certificate_sha256: p.certificate.sha256, issuer: p.certificate.issuer, signed_at: p.certificate.signed_at, ...(p.mandate_sha256 ? { mandate_sha256: p.mandate_sha256 } : {}) },
    mandate: p.mandate,
    kyb_snapshot: null,
    status: "active",
    status_reason: null,
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    issuer: p.issuer,
    verify_url: `${p.issuer}/v1/agents/${p.credential_id}`,
    revocation_url: `${p.issuer}/v1/agents/${p.credential_id}/status`
  };
}

export async function signCredential(c: Credential, privateKey: CryptoKey, keyId: string, now = new Date()): Promise<Credential> {
  const { attestation: _a, ...payload } = c;
  const attestation = await signAttestation(payload as unknown as Record<string, unknown>, privateKey, keyId, `${c.issuer}/v1/verify`, now);
  return { ...payload, attestation } as Credential;
}

export async function verifyCredentialSignature(c: Credential, publicJwk: JsonWebKey) {
  return verifyAttestation(c as unknown as Record<string, unknown>, publicJwk);
}

/** Stable hash of the credential content (what the signature covers). */
export async function credentialDigest(c: Credential): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalize(attestedPayload(c as unknown as Record<string, unknown>)));
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Whether the company can still answer for an agent (D-15): only its existence as a legal entity,
 * i.e. registration ATIVA at the Receita Federal. Sanctions, debt and risk are facts about the company
 * for the verifier to weigh with its own screening, never a reason to deny or suspend the credential.
 */
/** D-24: statuses that mean "not known", not "not active": the check was off or no source answered. */
export const UNKNOWN_REGISTRATION = ["UNVERIFIED", "NOT_CHECKED"];

export function principalDecision(registration_status: string): { ok: boolean; reason: string | null } {
  // Only a confirmed status other than ATIVA blocks; an unknown one is carried as a warning (D-24).
  if (UNKNOWN_REGISTRATION.includes(registration_status)) return { ok: true, reason: null };
  if (registration_status !== "ATIVA") return { ok: false, reason: `company is ${registration_status} at the Receita Federal` };
  return { ok: true, reason: null };
}

export function effectiveStatus(c: Pick<Credential, "status" | "expires_at">, now = new Date()): CredentialStatus {
  if (c.status === "active" && Date.parse(c.expires_at) < now.getTime()) return "expired";
  return c.status;
}

/** D-33: SHA-256 (lowercase hex) of the canonical JSON (section 7) of a mandate; what the challenge commits to. */
export async function mandateSha256(mandate: Mandate): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(mandate)));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Offline: does the ICP-Brasil signature behind this credential cover its mandate (D-33)?
 *   "signed"      authorized_by.mandate_sha256 equals the SHA-256 of credential.mandate;
 *   "mismatch"    it does not: the mandate is not the one the principal signed (refuse the credential);
 *   "not_covered" the credential predates D-33 and carries no hash: the mandate rests on the issuer's attestation.
 * The certificate signature itself is verified by the issuer at issuance; the signed .p7s stays with the principal.
 */
export async function verifyMandateAuthorization(c: Pick<Credential, "mandate" | "authorized_by">): Promise<"signed" | "mismatch" | "not_covered"> {
  const h = c.authorized_by?.mandate_sha256;
  if (!h) return "not_covered";
  return (await mandateSha256(c.mandate)) === h ? "signed" : "mismatch";
}

