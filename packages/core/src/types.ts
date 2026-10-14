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
export type AgentKeyKind = "evm" | "web-bot-auth" | "erc8004";

export interface AgentKey {
  kind: AgentKeyKind;
  /** evm: 0x address (checksummed). web-bot-auth: Ed25519 public key, base64url raw 32 bytes (RFC 9421 key id = JWK thumbprint). erc8004: eip155:<chainId>:<identityRegistry>:<agentId>. */
  id: string;
  /** erc8004 only: the agentWallet resolved on chain when the credential was issued; the key that signs for the agent. */
  wallet?: `0x${string}`;
}

export type CredentialStatus = "pending" | "active" | "suspended" | "revoked" | "expired";

/** Reserved mandate fields the `check_action` evaluator understands. Anything else is carried, not evaluated. */
/** One payment instrument in a mandate (D-25). */
export interface PaymentInstrument {
  /** Network or rail, lowercase: visa, mastercard, elo, amex, hipercard, pix, x402, ... */
  network: string;
  /** Lowercase hex SHA-256 of the network's reference (token reference, PAR, ...); see hashPaymentRef. */
  ref_sha256: string;
  /** Optional human label, e.g. "corporate card, purchasing". Never the card number. */
  label?: string;
}

/** What a mandate allows its agent to delegate (D-30). */
export interface DelegationPolicy {
  max_depth: number;
  max_ttl_seconds: number;
}

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
  /**
   * Payment instruments the agent may use (D-25): card network tokens, PARs or any reference a payment network
   * gives, never a card number. `ref_sha256` is the lowercase hex SHA-256 of the reference (UTF-8, whitespace
   * removed, case kept); empty or absent = any.
   */
  payment_instruments?: PaymentInstrument[];
  /**
   * Delegation to sub-agents (D-30): the agent may hand a narrower mandate to other keys, up to `max_depth`
   * levels below it, each delegation living at most `max_ttl_seconds`. Absent = the agent cannot delegate.
   */
  delegation?: DelegationPolicy;
  /** Mandate validity (ISO dates); the credential never outlives it. */
  valid_from?: string;
  valid_until?: string;
}

export type Mandate = MandateCore & Record<string, unknown>;

/** Legacy risk screen at issuance. Informative only since D-15, never filled since D-23; the shape stays in /v1 for compatibility. */
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

export interface CompanyPrincipal { kind?: "company"; cnpj: string; cnpj_formatted: string; legal_name: string; registration_status: string }
/** D-29: a person who signed with an e-CPF. Never a name, a CPF or a hash of it; verifiers check a CPF they know through the issuer. */
export interface PersonPrincipal { kind: "person"; verified_by: "icp-brasil-e-cpf" }
export const isPersonPrincipal = (p: CompanyPrincipal | PersonPrincipal): p is PersonPrincipal => (p as PersonPrincipal).kind === "person";

/** The credential: "this agent key acts for this company, within this mandate, verified on this date". */
export interface Credential {
  credential_id: string;
  version: 1;
  agent: AgentKey;
  /** A company (e-CNPJ) or, since D-29, a natural person (e-CPF) with no personal data: tell them apart by `kind`. */
  principal: CompanyPrincipal | PersonPrincipal;
  /** How the principal authorized it: hash of the ICP-Brasil certificate that signed the challenge. No subject for persons. */
  authorized_by: { method: "icp-brasil-e-cnpj" | "icp-brasil-e-cpf"; certificate_sha256: string; certificate_subject?: string; issuer: string; signed_at: string };
  mandate: Mandate;
  /** Informative since D-15: the issuance decision uses only principal.registration_status and the certificate's revocation status. Always null from the reference issuer since D-23 (no KYB dependency); kept in /v1. Null when the issuer has no KYB source (D-17). */
  kyb_snapshot: KybSnapshot | null;
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
    public code: "INVALID_INPUT" | "INVALID_CNPJ" | "NOT_FOUND" | "CHALLENGE_FAILED" | "CERTIFICATE_INVALID" | "CNPJ_MISMATCH" | "KYB_BLOCKED" | "KYB_UNAVAILABLE" | "CERTIFICATE_REVOKED" | "REVOCATION_UNAVAILABLE" | "REGISTRY_UNAVAILABLE" | "RATE_LIMITED" | "UPSTREAM_ERROR" | "CONFLICT",
    message: string
  ) {
    super(message);
    this.name = "KyaError";
  }
}
