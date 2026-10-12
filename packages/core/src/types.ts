/** Shared types of KYA Brasil. Within /v1 fields are only added, never renamed or removed. */

export interface Attestation {
  algorithm: "ed25519";
  key_id: string;
  sha256: string;
  signed_at: string;
  signature: string;
  verify_url: string;
}

/** How the agent proves it holds its key. */
export type AgentKeyKind = "evm" | "web-bot-auth";

export interface AgentKey {
  kind: AgentKeyKind;
  /** evm: 0x address (checksummed). web-bot-auth: Ed25519 public key, base64url raw 32 bytes (RFC 9421 key id = JWK thumbprint). */
  id: string;
}

export type CredentialStatus = "pending" | "active" | "suspended" | "revoked" | "expired";

/** Reserved mandate fields the `check_action` evaluator understands. Anything else is carried, not evaluated. */
export interface MandateCore {
  /** Actions the agent may take on behalf of the company (free vocabulary, lowercase: buy, sell, quote, pay, sign, ...). */
  actions?: string[];
  /** Per-operation ceiling. */
  max_per_operation?: { amount: number; currency: string };
  /** Per-day ceiling. */
  max_per_day?: { amount: number; currency: string };
  /** Currencies the agent may transact in (ISO 4217 or asset symbols such as USDC). */
  currencies?: string[];
  /** Counterparties the agent may deal with (CNPJs, domains or wallet addresses); empty = any. */
  counterparties?: string[];
  /** Mandate validity (ISO dates); the credential never outlives it. */
  valid_from?: string;
  valid_until?: string;
}

export type Mandate = MandateCore & Record<string, unknown>;

export interface KybSnapshot {
  risk_level: "low" | "medium" | "high" | "critical";
  risk_score: number;
  registration_status: string;
  active_sanctions: number;
  forced_labor: boolean;
  federal_debt_brl: number | null;
  active_embargoes: number;
  red_flags: string[];
  checked_at: string;
}

/** The credential: "this agent key acts for this company, within this mandate, verified on this date". */
export interface Credential {
  credential_id: string;
  version: 1;
  agent: AgentKey;
  principal: { cnpj: string; cnpj_formatted: string; legal_name: string; registration_status: string };
  /** How the company authorized it: hash of the e-CNPJ certificate that signed the challenge (never the CPF of the signer). */
  authorized_by: { method: "icp-brasil-e-cnpj"; certificate_sha256: string; certificate_subject: string; issuer: string; signed_at: string };
  mandate: Mandate;
  kyb_snapshot: KybSnapshot;
  status: CredentialStatus;
  status_reason: string | null;
  issued_at: string;
  expires_at: string;
  issuer: string;
  verify_url: string;
  revocation_url: string;
  attestation?: Attestation;
}

export class KyaError extends Error {
  constructor(
    public code: "INVALID_INPUT" | "INVALID_CNPJ" | "NOT_FOUND" | "CHALLENGE_FAILED" | "CERTIFICATE_INVALID" | "CNPJ_MISMATCH" | "KYB_BLOCKED" | "KYB_UNAVAILABLE" | "RATE_LIMITED" | "UPSTREAM_ERROR" | "CONFLICT",
    message: string
  ) {
    super(message);
    this.name = "KyaError";
  }
}
