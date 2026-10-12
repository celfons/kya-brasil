export const SERVICE_NAME = "KYA Brasil";
export const SERVICE_TAGS = ["brazil", "kya", "agent-identity", "kyb", "attestation"];
export const VERSION = "0.1.0";
export const HOMEPAGE = "https://kya-br-agents.marcelfons.workers.dev";
export const CONTACT_EMAIL = "matheuscoreggio@gmail.com";
export const SERVICE_DESCRIPTION =
  "Know-your-agent credentials for Brazil: a company proves with its e-CNPJ (ICP-Brasil) certificate that an AI agent key (EVM wallet or Web Bot Auth) acts on its behalf, within a declared mandate. KYB Brasil checks the company (Receita, CGU sanctions, forced labour, debt, embargoes) before issuance and every day after. Credentials are Ed25519-signed JSON, verifiable at a stable URL, revocable at once. Verification free up to 50/day per IP, then x402.";
export const MAX_DESCRIPTION = 480;

export const TOOLS = {
  kya_register: { priceUsd: 0.5, method: "POST", path: "/v1/agents", description: "Register an AI agent for a Brazilian company: agent key (EVM address or Web Bot Auth Ed25519 key), CNPJ and a mandate (JSON, validated against /.well-known/kya-mandate.schema.json). Returns a one-time challenge the agent signs with its key and the company signs with its e-CNPJ (CMS/PKCS#7). Price covers the KYB check at issuance." },
  kya_prove: { priceUsd: 0, method: "POST", path: "/v1/agents/{id}/prove", description: "Free. Send both signatures of the challenge. The e-CNPJ chain is validated against ICP-Brasil roots, the CNPJ must match, KYB Brasil must clear the company; then the credential is issued (90 days, Ed25519-signed)." },
  kya_verify: { priceUsd: 0, method: "GET", path: "/v1/agents/{id}", description: "Free (50/day per IP). The agent's current credential: principal company, mandate, KYB snapshot, status (active, suspended, revoked, expired) and signature. Also by key: /v1/agents/by-key?kind=&id=." },
  kya_verify_paid: { priceUsd: 0.01, method: "GET", path: "/v1/agents/{id}/verified", description: "Same as the free verification, without daily limit, plus a signed receipt of the verification itself (what was checked, when). Pay per call with x402." },
  kya_check_action: { priceUsd: 0.01, method: "GET", path: "/v1/agents/{id}/allowed", description: "Signed verdict: is this action (action, amount, currency, counterparty) inside the agent's mandate and is the credential active? Evaluates the reserved mandate fields; lists the fields it did not evaluate." },
  kya_renew: { priceUsd: 0.1, method: "POST", path: "/v1/agents/{id}/renew", description: "Re-issue the credential for 90 more days if KYB Brasil still clears the company. The company signs the renewal challenge with its e-CNPJ." },
  kya_revoke: { priceUsd: 0, method: "POST", path: "/v1/agents/{id}/revoke", description: "Free. The company revokes the credential at once (e-CNPJ-signed request). Revocations are listed at /v1/revocations." }
} as const;
export type ToolName = keyof typeof TOOLS;
