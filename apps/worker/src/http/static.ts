import { MANDATE_SCHEMA } from "@kya-br/core";
import { CONTACT_EMAIL, REGISTRY_DESCRIPTION, REGISTRY_NAME, SERVICE_DESCRIPTION, SERVICE_NAME, TOOLS, VERSION, type ToolName } from "../pricing";

export function mandateSchema(origin: string) {
  return { ...MANDATE_SCHEMA, $id: `${origin}/.well-known/kya-mandate.schema.json` };
}

export function openapiJson(origin: string, network: string, payTo: string) {
  const paths: Record<string, unknown> = {};
  const envelope = { type: "object" };
  const err = { type: "object", properties: { error: { type: "string" }, message: { type: "string" } } };
  for (const [name, t] of Object.entries(TOOLS) as [ToolName, (typeof TOOLS)[ToolName]][]) {
    const paid = t.priceUsd > 0;
    const op = {
      operationId: name,
      summary: name.replace("kya_", "").replace(/_/g, " "),
      description: t.description,
      tags: [paid ? "paid" : "free"],
      "x-tool": name,
      "x-price-usd": t.priceUsd,
      ...(t.path.includes("{id}") ? { parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" }, description: "credential_id" }] } : {}),
      ...(t.method === "POST" ? { requestBody: { required: true, content: { "application/json": { schema: { type: "object" } } } } } : {}),
      responses: {
        "200": { description: "OK", content: { "application/json": { schema: envelope } } },
        "400": { description: "Invalid input (never charged)", content: { "application/json": { schema: err } } },
        ...(paid ? { "402": { description: "Payment required: PAYMENT-REQUIRED header (x402); retry with PAYMENT-SIGNATURE." } } : { "429": { description: "Free tier limit (per IP, per day)" } }),
        "404": { description: "Unknown credential" },
        "409": { description: "State conflict (already active, revoked)" },
        "422": { description: "Proof rejected: challenge, e-CNPJ, CNPJ mismatch or KYB blocked (never charged twice)" }
      }
    };
    paths[t.path] = { ...(paths[t.path] as object), [t.method.toLowerCase()]: op };
  }
  paths["/v1/agents/{id}/allowed"] = {
    get: {
      ...(paths["/v1/agents/{id}/allowed"] as { get: object }).get,
      parameters: [
        { name: "id", in: "path", required: true, schema: { type: "string" } },
        { name: "action", in: "query", schema: { type: "string" } },
        { name: "amount", in: "query", schema: { type: "number" } },
        { name: "currency", in: "query", schema: { type: "string" } },
        { name: "counterparty", in: "query", schema: { type: "string" }, description: "CNPJ, domain or wallet address" },
        { name: "spent_today", in: "query", schema: { type: "number" }, description: "What this agent already spent today, if you track it" }
      ]
    }
  };
  return {
    openapi: "3.1.0",
    info: { title: SERVICE_NAME, version: VERSION, description: SERVICE_DESCRIPTION, contact: { email: CONTACT_EMAIL } },
    servers: [{ url: origin }],
    "x-x402": { version: 2, network, payTo, asset: "USDC", note: "Paid routes answer 402 with PAYMENT-REQUIRED; errors are never charged." },
    "x-attestation": { public_key: `${origin}/.well-known/kya.json`, verify: `POST ${origin}/v1/verify`, note: "Credentials and verdicts carry attestation {sha256, signed_at, signature, key_id}: Ed25519 over the canonical JSON without attestation." },
    tags: [{ name: "free" }, { name: "paid" }],
    paths
  };
}

export function llmsTxt(origin: string, network: string): string {
  const tools = (Object.keys(TOOLS) as ToolName[]).map((n) => `- ${n} (${TOOLS[n].priceUsd === 0 ? "free" : `$${TOOLS[n].priceUsd.toFixed(2)} USDC per call`}): ${TOOLS[n].method} ${origin}${TOOLS[n].path}. ${TOOLS[n].description}`).join("\n");
  return `# ${SERVICE_NAME}

> ${SERVICE_DESCRIPTION} Network: ${network}.

## When to use
- Before accepting an action or a payment from an AI agent that claims to act for a Brazilian company: GET ${origin}/v1/agents/{credential_id} (or /v1/agents/by-key?kind=evm&id=0x...) and check status == "active".
- Before letting an agent do something specific: GET ${origin}/v1/agents/{id}/allowed?action=pay&amount=80&currency=USDC&counterparty=<cnpj> returns a signed allowed/denied verdict.
- To give your own agent a credential: POST /v1/agents, sign the challenge with the agent key and with the company's e-CNPJ, POST /v1/agents/{id}/prove.

## Tools
${tools}

## Credential
JSON signed with Ed25519 (attestation.key_id, public keys at ${origin}/.well-known/kya.json). Fields: credential_id, agent {kind, id}, principal {cnpj, legal_name, registration_status}, authorized_by {method, certificate_sha256, certificate_subject, issuer, signed_at}, mandate (JSON validated by ${origin}/.well-known/kya-mandate.schema.json; reserved fields: actions, max_per_operation, max_per_day, currencies, counterparties, valid_from, valid_until), kyb_snapshot, status, issued_at, expires_at (90 days or the mandate's end), verify_url, revocation_url. Status changes after issuance (suspended by the daily KYB review, revoked by the company) are reported live at verify_url and in ${origin}/v1/revocations; the signature covers the credential as issued.

## Rules
- Legal entities only: no CPF is stored or returned; the signer of the e-CNPJ is identified by the certificate hash.
- Errors (400, 404, 409, 422) are never charged. Free verification: 50/day per IP; paid verification has no limit.
- Within /v1 fields are only added, never renamed or removed.

## Machine-readable
OpenAPI: ${origin}/openapi.json. Status: ${origin}/status. Terms: ${origin}/terms. Contact: ${CONTACT_EMAIL}.
`;
}

export function termsText(): string {
  return `${SERVICE_NAME} terms (summary)
1. The service attests that a company, identified by its e-CNPJ certificate, declared that an agent key acts for it within a mandate, and that KYB Brasil cleared the company on the dates shown. It does not observe or guarantee what the agent does.
2. The company that signs the mandate answers for the agent's actions inside it. The issuer answers only for the verification it performed.
3. Credentials expire in 90 days, are suspended when the company no longer clears KYB, and are revoked at once on the company's signed request.
4. Personal data: only legal-entity data and the certificate hash are stored. No CPF, no signer identity.
5. Errors are never charged. Best effort, no SLA.
6. Contact: ${CONTACT_EMAIL}`;
}

/** MCP Registry entry (published by the CD on prod; see .github/workflows/cd.yml). */
export function serverJson(origin: string): unknown {
  return {
    $schema: "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
    name: REGISTRY_NAME,
    description: REGISTRY_DESCRIPTION,
    version: VERSION,
    websiteUrl: origin,
    icons: [{ src: `${origin}/icon.svg`, mimeType: "image/svg+xml", sizes: ["any"] }],
    remotes: [{ type: "streamable-http", url: `${origin}/mcp` }]
  };
}

/** Square icon for MCP clients and directories: a shield in Brazil's colors with a key, "KYA". */
export const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <rect width="128" height="128" rx="24" fill="#0B2E4F"/>
  <path d="M64 14 L104 28 V62 C104 88 86 106 64 114 C42 106 24 88 24 62 V28 Z" fill="#002776"/>
  <path d="M64 30 L94 62 L64 94 L34 62 Z" fill="#FFDF00"/>
  <circle cx="64" cy="62" r="17" fill="#009C3B"/>
  <text x="64" y="68" font-family="Arial, Helvetica, sans-serif" font-size="15" font-weight="700" fill="#FFFFFF" text-anchor="middle">KYA</text>
</svg>`;
