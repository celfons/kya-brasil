import { MANDATE_SCHEMA } from "@kya-brasil/core";
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
      ...(/\{(\w+)\}/.test(t.path) ? { parameters: [...t.path.matchAll(/\{(\w+)\}/g)].map((m) => ({ name: m[1], in: "path", required: true, schema: { type: "string" }, description: m[1] === "id" ? "credential_id" : m[1] })) } : {}),
      ...(t.method === "POST" ? { requestBody: { required: true, content: { "application/json": { schema: { type: "object" } } } } } : {}),
      responses: {
        "200": { description: "OK", content: { "application/json": { schema: envelope } } },
        "400": { description: "Invalid input (never charged)", content: { "application/json": { schema: err } } },
        ...(paid ? { "402": { description: "Payment required: PAYMENT-REQUIRED header (x402); retry with PAYMENT-SIGNATURE." } } : { "429": { description: "Free tier limit (per IP, per day)" } }),
        "404": { description: "Unknown credential" },
        "409": { description: "State conflict (already active, revoked)" },
        "422": { description: "Proof rejected: challenge, e-CNPJ invalid or revoked, CNPJ mismatch or company not ATIVA (never charged twice)" }
      }
    };
    paths[t.path] = { ...(paths[t.path] as object), [t.method.toLowerCase()]: op };
  }
  paths["/v1/agents/{id}/sign-link"] = {
    get: {
      ...(paths["/v1/agents/{id}/sign-link"] as { get: object }).get,
      parameters: [
        { name: "id", in: "path", required: true, schema: { type: "string" } },
        { name: "challenge_id", in: "query", required: true, schema: { type: "string" } },
        { name: "agent_signature", in: "query", schema: { type: "string" }, description: "The agent's signature of challenge.text" }
      ]
    }
  };
  paths["/v1/agents/{id}/allowed"] = {
    get: {
      ...(paths["/v1/agents/{id}/allowed"] as { get: object }).get,
      parameters: [
        { name: "id", in: "path", required: true, schema: { type: "string" } },
        { name: "action", in: "query", schema: { type: "string" } },
        { name: "amount", in: "query", schema: { type: "number" } },
        { name: "currency", in: "query", schema: { type: "string" } },
        { name: "counterparty", in: "query", schema: { type: "string" }, description: "CNPJ, domain or wallet address" },
        { name: "spent_today", in: "query", schema: { type: "number" }, description: "What this agent already spent today, if you track it" },
        { name: "payment_network", in: "query", schema: { type: "string" }, description: "Payment network or rail: visa, mastercard, elo, pix, ..." },
        { name: "payment_ref_sha256", in: "query", schema: { type: "string", pattern: "^[0-9a-f]{64}$" }, description: "SHA-256 hex of the payment token reference or PAR (never a card number), checked against mandate.payment_instruments" }
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
- The e-CNPJ step is a person's: send them the registration's sign_url with &agent_signature=<your signature> appended. They open ${origin}/sign, see the agent and mandate, sign in the browser (.pfx, or a .p7s from any ICP-Brasil signer) and the credential is issued. Do not ask for or hold the company's certificate or password yourself.
- Payment networks, acquirers and issuers: mandate.payment_instruments lists the instruments the agent may use, as SHA-256 of the network's token reference or PAR (never a card number). Pass payment_network and payment_ref_sha256 to /allowed and the signed verdict says whether that instrument belongs to an agent authorized by that CNPJ. The same checks run offline with the npm library @kya-brasil/core (checkAction, hashPaymentRef).
- max_per_day is checked against the spent_today you pass to /allowed: the issuer does not record what agents do. Keep your own records of accepted actions.
- A company sees every agent registered in its name with POST ${origin}/v1/companies/{cnpj}/agents and gets signed events (issued, renewed, suspended, reinstated, revoked) at the webhook it sets with POST ${origin}/v1/companies/{cnpj}/webhook; both free and signed with its e-CNPJ.
- Offline verification (issuer signature on the credential) proves what was issued, not that it is still active: check status online, or accept the risk until expires_at.

## Tools
${tools}

## Credential
JSON signed with Ed25519 (attestation.key_id, public keys at ${origin}/.well-known/kya.json). Fields: credential_id, agent {kind, id}, principal {cnpj, legal_name, registration_status (ATIVA; UNVERIFIED or NOT_CHECKED when the check was unavailable or off, with the reason in the issuance response's warnings)}, authorized_by {method, certificate_sha256, certificate_subject, issuer, signed_at}, mandate (JSON validated by ${origin}/.well-known/kya-mandate.schema.json; reserved fields: actions, max_per_operation, max_per_day, currencies, counterparties, valid_from, valid_until), kyb_snapshot (always null; kept for /v1 compatibility), status, issued_at, expires_at (90 days or the mandate's end), verify_url, revocation_url. Status changes after issuance (daily review: revoked when the e-CNPJ is revoked at its AC, suspended while the company is not ATIVA or the certificate is on hold; revoked by the company) are reported live at verify_url and in ${origin}/v1/revocations; the signature covers the credential as issued.

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
1. The service attests that a company, identified by its e-CNPJ certificate, declared that an agent key acts for it within a mandate, that the certificate was not revoked and that the company was ATIVA at the Receita Federal on the dates shown. It does not assess the company's risk (sanctions, debt, litigation: see KYB Brasil) and does not observe or guarantee what the agent does.
2. The company that signs the mandate answers for the agent's actions inside it. The issuer answers only for the verification it performed.
3. Credentials expire in 90 days, are suspended while the company is not ATIVA, are revoked when the e-CNPJ that authorized them is revoked at its AC, and are revoked at once on the company's signed request.
4. Personal data: only legal-entity data and the certificate hash are stored. No CPF, no signer identity.
5. Errors are never charged. Best effort, no SLA. Live state is published at /status (including the last daily review); while the issuer is unreachable, a verifier decides whether to accept a credential checked only offline, until its expires_at.
6. The issuer does not record what agents do. A company may watch its agents through the inventory and the signed webhook events.
7. Contact: ${CONTACT_EMAIL}`;
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

/** Swagger UI for humans evaluating the API; the spec itself is /openapi.json. */
export function docsHtml(origin: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KYA Brasil API</title>
<link rel="icon" href="${origin}/icon.svg">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui.min.css">
<style>body{margin:0;background:#fff}.topbar{display:none}</style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui-bundle.min.js" crossorigin="anonymous"></script>
<script>
window.ui = SwaggerUIBundle({ url: "${origin}/openapi.json", dom_id: "#swagger-ui", deepLinking: true, tryItOutEnabled: true, defaultModelsExpandDepth: 0 });
</script>
</body>
</html>`;
}

/**
 * Landing page for humans who open the origin in a browser (agents and curl get the JSON index: the
 * route negotiates on Accept). Live figures come from /status; everything else is static.
 */
export function landingHtml(origin: string, network: string): string {
  const rows = (Object.keys(TOOLS) as ToolName[])
    .map((n) => `<tr><td><code>${n}</code></td><td><code>${TOOLS[n].method} ${TOOLS[n].path}</code></td><td class="p">${TOOLS[n].priceUsd === 0 ? "free" : `$${TOOLS[n].priceUsd.toFixed(2)}`}</td></tr>`)
    .join("");
  const esc = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${SERVICE_NAME}</title>
<meta name="description" content="${esc(SERVICE_DESCRIPTION)}">
<link rel="icon" href="${origin}/icon.svg">
<style>
:root{--bg:#f7f7f4;--fg:#1d2129;--muted:#5d6470;--line:#d4d8de;--panel:#fff;--accent:#0b6e4f;--money:#9a4d00}
@media(prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e8eaee;--muted:#a0a7b2;--line:#3a414b;--panel:#1c2128;--accent:#4fc69a;--money:#e5a04a;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:28px 16px 48px}
main{max-width:900px;margin:0 auto;display:grid;gap:28px}h1{font-size:1.8rem;margin:0 0 4px}h2{font-size:1.05rem;margin:0 0 8px}p{margin:0;max-width:72ch}
.lead{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 12px}.tile b{display:block;font-size:.75rem;letter-spacing:.04em;text-transform:uppercase;color:var(--muted)}
.tile span{font-variant-numeric:tabular-nums;word-break:break-all}.ok{color:var(--accent)}
nav{display:flex;flex-wrap:wrap;gap:8px}nav a{border:1px solid var(--line);border-radius:999px;padding:4px 12px;text-decoration:none;color:var(--fg);background:var(--panel)}nav a:hover{border-color:var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden}td,th{padding:8px 10px;border-top:1px solid var(--line);text-align:left;vertical-align:top}th{border-top:0;font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.p{white-space:nowrap;color:var(--money);font-variant-numeric:tabular-nums}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em}pre{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px;overflow-x:auto;margin:0}
.wrap{overflow-x:auto}footer{color:var(--muted);font-size:.9rem}a{color:var(--accent)}
</style>
</head>
<body>
<main>
<header>
<h1>${SERVICE_NAME}</h1>
<p class="lead">${esc(SERVICE_DESCRIPTION)}</p>
</header>
<nav>
<a href="${origin}/docs">API (Swagger)</a><a href="${origin}/llms.txt">llms.txt</a><a href="${origin}/openapi.json">openapi.json</a>
<a href="${origin}/mcp">MCP endpoint</a><a href="https://www.npmjs.com/package/@kya-brasil/agent-tools">npm client</a>
<a href="https://github.com/celfons/kya-brasil">GitHub</a><a href="https://github.com/celfons/kya-brasil/blob/main/docs/SPEC.md">Spec</a>
<a href="${origin}/.well-known/kya.json">Signing keys</a><a href="${origin}/status">status.json</a><a href="${origin}/terms">Terms</a>
</nav>
<section>
<h2>Live</h2>
<div class="grid" id="live">
<div class="tile"><b>Version</b><span id="v">${VERSION}</span></div>
<div class="tile"><b>Network</b><span>${network}</span></div>
<div class="tile"><b>Signing key</b><span id="k">loading</span></div>
<div class="tile"><b>Credentials</b><span id="c">loading</span></div>
<div class="tile"><b>Registration source</b><span id="r">loading</span></div>
<div class="tile"><b>Last daily review</b><span id="d">loading</span></div>
</div>
</section>
<section>
<h2>Tools and prices (USDC, x402 on ${network})</h2>
<div class="wrap"><table><thead><tr><th>Tool</th><th>HTTP</th><th>Price</th></tr></thead><tbody>${rows}</tbody></table></div>
</section>
<section>
<h2>Verify a credential from a terminal</h2>
<pre>curl ${origin}/v1/agents/&lt;credential_id&gt;
curl "${origin}/v1/agents/&lt;credential_id&gt;/allowed?action=pay&amp;amount=80&amp;currency=USDC"   # 402: pay with x402, or use the npm client</pre>
</section>
<footer>Agents get JSON here (<code>Accept: application/json</code>). Errors are never charged. No CPF is stored.</footer>
</main>
<script>
(async()=>{try{const s=await (await fetch("${origin}/status")).json();const q=(i)=>document.getElementById(i);
q("v").textContent=s.version;q("k").textContent=s.attestation_key||"none";q("k").className=s.attestation_key?"ok":"";
const c=s.credentials||{};q("c").textContent=Object.keys(c).length?Object.entries(c).map(([k,v])=>k+" "+v).join(", "):"none yet";
q("r").textContent=s.registration_check==="off"?"off":(s.registration_sources||[]).join(", ")||"-";const d=s.daily_review;q("d").textContent=d&&d.ran_at?new Date(d.ran_at).toISOString().slice(0,16).replace("T"," ")+" UTC":d&&d.at?new Date(d.at).toISOString().slice(0,16).replace("T"," ")+" UTC":"not yet";}
catch(e){for(const i of["k","c","r","d"])document.getElementById(i).textContent="unavailable"}})();
</script>
</body>
</html>`;
}
