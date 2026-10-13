/**
 * Credential assembly, signing and verification. The signature is the same Ed25519 attestation
 * used by KYB Brasil (SHA-256 of the canonical JSON without `attestation`), so one public key
 * document verifies both products and the SDK's verifyAttestation() works unchanged.
 */
import { attestedPayload, canonicalize, signAttestation, verifyAttestation } from "./attestation";
import { formatCnpj, normalizeCnpj } from "./cnpj";
import type { Credential, CredentialStatus, KybSnapshot, Mandate, AgentKey } from "./types";

export const CREDENTIAL_TTL_DAYS = 90;

export function buildCredential(p: {
  credential_id: string;
  agent: AgentKey;
  cnpj: string;
  legal_name: string;
  registration_status: string;
  certificate: { sha256: string; subject: string; issuer: string; signed_at: string };
  mandate: Mandate;
  kyb: KybSnapshot | null;
  issuer: string;
  now?: Date;
  status?: CredentialStatus;
  status_reason?: string | null;
}): Credential {
  const now = p.now ?? new Date();
  const cnpj = normalizeCnpj(p.cnpj);
  const ttl = new Date(now.getTime() + CREDENTIAL_TTL_DAYS * 86400000);
  const mandateEnd = p.mandate.valid_until ? new Date(p.mandate.valid_until) : null;
  const expires = mandateEnd && mandateEnd < ttl ? mandateEnd : ttl;
  return {
    credential_id: p.credential_id,
    version: 1,
    agent: p.agent,
    principal: { cnpj, cnpj_formatted: formatCnpj(cnpj), legal_name: p.legal_name, registration_status: p.registration_status },
    authorized_by: { method: "icp-brasil-e-cnpj", certificate_sha256: p.certificate.sha256, certificate_subject: p.certificate.subject, issuer: p.certificate.issuer, signed_at: p.certificate.signed_at },
    mandate: p.mandate,
    kyb_snapshot: p.kyb,
    status: p.status ?? "active",
    status_reason: p.status_reason ?? null,
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
 * for the verifier to weigh (KYB Brasil), never a reason to deny or suspend the credential.
 */
export function principalDecision(registration_status: string): { ok: boolean; reason: string | null } {
  if (registration_status !== "ATIVA") return { ok: false, reason: `company is ${registration_status} at the Receita Federal` };
  return { ok: true, reason: null };
}

export function effectiveStatus(c: Pick<Credential, "status" | "expires_at">, now = new Date()): CredentialStatus {
  if (c.status === "active" && Date.parse(c.expires_at) < now.getTime()) return "expired";
  return c.status;
}
