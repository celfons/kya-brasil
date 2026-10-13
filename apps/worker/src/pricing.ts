export const SERVICE_NAME = "KYA Brasil";
export const SERVICE_TAGS = ["brazil", "kya", "agent-identity", "kyb", "attestation"];
export const VERSION = "0.3.0";
export const REGISTRY_NAME = "io.github.celfons/kya-brasil";
/** MCP Registry entry (≤100 chars). */
export const REGISTRY_DESCRIPTION = "KYA backed by a real company: e-CNPJ-signed agent mandates, KYB-checked daily, signed verdicts";
export const HOMEPAGE = "https://kya-br-agents.marcelfons.workers.dev";
export const CONTACT_EMAIL = "matheuscoreggio@gmail.com";
export const SERVICE_DESCRIPTION =
  "KYA backed by a real company. A Brazilian company signs with its e-CNPJ (ICP-Brasil) that an AI agent key (EVM, Web Bot Auth or ERC-8004) acts for it within a mandate; KYB Brasil checks the company (Receita, sanctions, forced labour, debt, embargoes) at issuance and every day. Credentials are Ed25519-signed, verifiable offline, revocable at once; every per-action verdict is signed. Verification free up to 50/day per IP, then x402.";
export const MAX_DESCRIPTION = 480;

export const TOOLS = {
  kya_register: { priceUsd: 0.5, method: "POST", path: "/v1/agents", description: "Register an AI agent for a Brazilian company: agent key (EVM address or Web Bot Auth Ed25519 key), CNPJ and a mandate (JSON, validated against /.well-known/kya-mandate.schema.json). Returns a one-time challenge the agent signs with its key and the company signs with its e-CNPJ (CMS/PKCS#7). Price covers the KYB check at issuance." },
  kya_prove: { priceUsd: 0, method: "POST", path: "/v1/agents/{id}/prove", description: "Free. Send both signatures of the challenge. The e-CNPJ chain is validated against ICP-Brasil roots, the CNPJ must match, KYB Brasil must clear the company; then the credential is issued (90 days, Ed25519-signed)." },
  kya_verify: { priceUsd: 0, method: "GET", path: "/v1/agents/{id}", description: "Free (50/day per IP). The agent's current credential: principal company, mandate, KYB snapshot, status (active, suspended, revoked, expired) and signature. Also by key: /v1/agents/by-key?kind=&id=." },
  kya_verify_paid: { priceUsd: 0.01, method: "GET", path: "/v1/agents/{id}/verified", description: "Same as the free verification, without daily limit, plus a signed receipt of the verification itself (what was checked, when). Pay per call with x402." },
  kya_check_action: { priceUsd: 0.01, method: "GET", path: "/v1/agents/{id}/allowed", description: "Signed verdict: is this action (action, amount, currency, counterparty) inside the agent's mandate and is the credential active? Evaluates the reserved mandate fields; lists the fields it did not evaluate." },
  kya_renew: { priceUsd: 0.1, method: "POST", path: "/v1/agents/{id}/renew", description: "Re-issue the credential for 90 more days if KYB Brasil still clears the company. The company signs the renewal challenge with its e-CNPJ." },
  kya_register_act: { priceUsd: 0.02, method: "POST", path: "/v1/agents/{id}/acts", description: "Register what the agent did (action, amount, currency, counterparty, reference, optional document hash and agent signature), usually by the party that accepted it. The issuer checks it against the mandate, adding what was already registered today, and returns a signed receipt. Denied acts are recorded too. The receipt is the proof of what the agent could and did do at that moment." },
  kya_act: { priceUsd: 0, method: "GET", path: "/v1/acts/{act_id}", description: "Free. A registered act and its signed receipt, by act_id (the receipt holder has it)." },
  kya_acts_export: { priceUsd: 0, method: "POST", path: "/v1/agents/{id}/acts/export", description: "Free. The company's trail of everything registered for one of its agents (default 30 days). The request is signed with the company's e-CNPJ, so only the principal reads it." },
  kya_revoke: { priceUsd: 0, method: "POST", path: "/v1/agents/{id}/revoke", description: "Free. The company revokes the credential at once (e-CNPJ-signed request). Revocations are listed at /v1/revocations." }
} as const;
export type ToolName = keyof typeof TOOLS;
