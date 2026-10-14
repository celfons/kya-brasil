export const SERVICE_NAME = "KYA Brasil";
export const SERVICE_TAGS = ["brazil", "kya", "agent-identity", "e-cnpj", "attestation"];
export const VERSION = "0.7.0";
export const REGISTRY_NAME = "io.github.celfons/kya-brasil";
/** MCP Registry entry (≤100 chars). */
export const REGISTRY_DESCRIPTION = "KYA backed by a real company: e-CNPJ-signed agent mandates, revocation-checked, signed verdicts";
export const HOMEPAGE = "https://kya-br-agents.marcelfons.workers.dev";
export const CONTACT_EMAIL = "marcelfons@gmail.com";
export const SERVICE_DESCRIPTION =
  "KYA backed by a real company. A Brazilian company signs with its e-CNPJ (ICP-Brasil) that an AI agent key (EVM, Web Bot Auth or ERC-8004) acts for it within a mandate. Every day the issuer checks that the e-CNPJ is not revoked (ICP-Brasil CRL) and the company is still ATIVA at the Receita; risk (sanctions, debt) is the verifier's call. Credentials are Ed25519-signed, verifiable offline, revocable at once; every per-action verdict is signed. Verification free up to 50/day per IP, then x402.";
export const MAX_DESCRIPTION = 480;

export const TOOLS = {
  kya_register: { priceUsd: 0.25, method: "POST", path: "/v1/agents", description: "Register an AI agent for a Brazilian company: agent key (EVM address or Web Bot Auth Ed25519 key), CNPJ and a mandate (JSON, validated against /.well-known/kya-mandate.schema.json). Returns a one-time challenge the agent signs with its key and the company signs with its e-CNPJ (CMS/PKCS#7). Price covers the checks at issuance." },
  kya_prove: { priceUsd: 0, method: "POST", path: "/v1/agents/{id}/prove", description: "Free. Send both signatures of the challenge. The e-CNPJ chain is validated against ICP-Brasil roots, the CNPJ must match, the certificate must not be revoked (CRL) and the company must be ATIVA; then the credential is issued (90 days, Ed25519-signed)." },
  kya_verify: { priceUsd: 0, method: "GET", path: "/v1/agents/{id}", description: "Free (50/day per IP). The agent's current credential: principal company, mandate, status (active, suspended, revoked, expired) and signature. Also by key: /v1/agents/by-key?kind=&id=." },
  kya_verify_paid: { priceUsd: 0.01, method: "GET", path: "/v1/agents/{id}/verified", description: "Same as the free verification, without daily limit, plus a signed receipt of the verification itself (what was checked, when). Pay per call with x402." },
  kya_check_action: { priceUsd: 0.01, method: "GET", path: "/v1/agents/{id}/allowed", description: "Signed verdict: is this action (action, amount, currency, counterparty, payment instrument) inside the agent's mandate and is the credential active? Evaluates the reserved mandate fields; lists the fields it did not evaluate." },
  kya_renew: { priceUsd: 0.1, method: "POST", path: "/v1/agents/{id}/renew", description: "Re-issue the credential for 90 more days. The company signs the renewal challenge with an e-CNPJ in force (not revoked); the company must still be ATIVA at the Receita." },
  kya_company_agents: { priceUsd: 0, method: "POST", path: "/v1/companies/{cnpj}/agents", description: "Free, company only. Every credential ever registered for your CNPJ, any status, whoever held the certificate (an accountant, another employee). Request signed with your e-CNPJ over \"KYA Brasil: agents <cnpj>\" + \"at: <ISO time>\"." },
  kya_company_webhook: { priceUsd: 0, method: "POST", path: "/v1/companies/{cnpj}/webhook", description: "Free, company only. Sets the https URL that receives signed events about your agents: credential issued, renewed, suspended, reinstated, revoked. Request signed with your e-CNPJ; url \"-\" removes it." },
  kya_revoke: { priceUsd: 0, method: "POST", path: "/v1/agents/{id}/revoke", description: "Free. The company revokes the credential at once (e-CNPJ-signed request). Revocations are listed at /v1/revocations." }
} as const;
export type ToolName = keyof typeof TOOLS;
