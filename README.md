# KYA Brasil

**Know-your-agent, backed by a real company.** Most "KYA" tools prove that an agent holds a key and give it
a score. KYA Brasil answers the question a supplier, a bank or a marketplace actually asks: **which legal
entity answers for this agent, and what is it allowed to do?**

A Brazilian company signs with its **e-CNPJ** (the ICP-Brasil certificate every company already uses for
invoices) that an AI agent key acts on its behalf, within a declared **mandate**. Before issuance and every
day after, the issuer checks that the e-CNPJ is not revoked (the AC's CRL) and that the company is still
active at the Receita Federal: the link between agent and company stays true or the credential stops working.
The credential is Ed25519-signed JSON: verifiable offline, live status at a stable URL, revocable at once.
Every per-action verdict is signed too.

KYA Brasil answers *who speaks for whom*, not *whether the company is a good risk*. Sanctions, forced
labour, debt and litigation are your call as the verifier: [KYB Brasil](https://kyb-br-agents.marcelfons.workers.dev)
answers those, with the CNPJ the credential gives you.

| | |
| --- | --- |
| Service | `https://kya-br-agents.marcelfons.workers.dev` |
| MCP (streamable HTTP) | `https://kya-br-agents.marcelfons.workers.dev/mcp` |
| MCP Registry | `io.github.celfons/kya-brasil` |
| npm | [`@kya-brasil/agent-tools`](https://www.npmjs.com/package/@kya-brasil/agent-tools) |
| Payments | [x402](https://x402.org), USDC on Base, no signup. Free verification up to 50/day per IP. Errors are never charged. |
| Spec | [docs/SPEC.md](docs/SPEC.md) with [test vectors](docs/vectors/credential-v1.json) |
| License | MIT |

## Why this is different

| | Key-only KYA (DID, score, bonds) | Policy gateways (release tokens, provenance) | **KYA Brasil** |
| --- | --- | --- | --- |
| Who answers for the agent | nobody, a key | the agent's own operator | **a legal entity, proven by e-CNPJ** |
| Link kept true | no | no | **e-CNPJ revocation (CRL) and company registration checked at issuance and daily** |
| Mandate (what the agent may do) | no | operator policy | **declared and signed by the company** |
| Verdict per action | score | allow / deny | **signed allow / deny with the checks listed** |
| Record of what the agent did | no | hash-chained ledger, self-declared | **signed receipt per act, daily ceilings enforced across counterparties, trail readable by the company** |
| Verifiable offline | sometimes | no | **yes, Ed25519 + published keys** |
| Open specification and code | rarely | no | **yes** |

## For verifiers: you receive an action from someone else's agent

Three calls, no account:

```ts
import { createKyaClient, verifyAttestation } from "@kya-brasil/agent-tools";

const kya = createKyaClient();                                    // add { privateKey } for paid calls
const v = await kya.verify(credentialId);                         // free: company, mandate, live status
if (v.status !== "active") reject();

const verdict = await kya.allowed(credentialId, {                 // $0.01, signed
  action: "order", amount: 4200, currency: "BRL", counterparty: "12345678000190"
});
if (!verdict.allowed) reject(verdict.reason);
await verifyAttestation(verdict);                                 // the issuer's signature, checked locally
```

Also check that the key that signed the agent's request is `v.agent.id` (or `v.agent.wallet` for ERC-8004):
a credential id alone proves nothing about who is talking.

Once you accept the action, **register it** ($0.02): the issuer re-checks the mandate including everything
registered today by anyone, so a daily ceiling holds across all the agent's counterparties, and signs a receipt
that is your proof of what the agent could and did do. The company reads the trail of its agents with its e-CNPJ.

```ts
const receipt = await kya.registerAct(credentialId, { action: "order", amount: 4200, currency: "BRL", counterparty: "12345678000190", reference: "PO-1" });
// receipt.allowed, receipt.spent_today_registered_after, receipt.receipt_url, receipt.attestation
```

Over MCP, the same three tools are `kya_verify`, `kya_check_action` and `kya_verify_paid`. Claude Desktop,
Cursor and friends: add the remote server `https://kya-br-agents.marcelfons.workers.dev/mcp`, no auth.

### Sign in with KYA (one middleware instead of three calls)

The agent signs every request with its key and sends four `KYA-*` headers; your server verifies the signature,
fetches and caches the credential, and gets who the agent is, which company answers for it and its mandate.
Hono, Express, Workers, Next, Bun, Deno: anything with a Web-standard `Request`.

```ts
import { createKyaAuth } from "@kya-brasil/agent-tools";
const auth = createKyaAuth();

app.use("/api/*", auth.hono());                                  // or auth.express(), or auth.fetchHandler(handler)
app.post("/api/orders", (c) => {
  const kya = c.get("kya");                                       // { credential_id, agent, principal, mandate, check(), allowed() }
  if (!kya.check({ action: "order", amount: 4200, currency: "BRL", counterparty: "12345678000190" }).allowed) return c.json({ error: "outside the mandate" }, 403);
  // ... accept, then kya.client.registerAct(kya.credential_id, { action: "order", amount: 4200, currency: "BRL", counterparty: "12345678000190" })
});
```

On the agent side, `signRequest({ credentialId, key, method, url, body })` returns the headers. Profile in
[docs/SPEC.md](docs/SPEC.md) section 14.

**Agent to agent (mutual):** the callee signs its response too (`signResponse`, bound to the request), and the
caller's `createKyaAgent(...).fetch(url)` signs the request and verifies who answered:

```ts
const alfa = createKyaAgent({ credentialId, key: { kind: "evm", privateKey } });
const { response, callee } = await alfa.fetch("https://beta.com.br/orders", { method: "POST", body });
if (callee?.ok) console.log("answered by", callee.kya.principal.legal_name);   // BETA SA, credential active
```

## For companies: give your own agent a credential

1. `POST /v1/agents` ($0.50) with the agent key, your CNPJ and a mandate. Returns a one-time challenge.
2. The agent signs the challenge with its key; you sign it with the e-CNPJ (detached CMS/PKCS#7).
3. `POST /v1/agents/{id}/prove` (free). The issuer validates both signatures, the certificate chain against
   the ICP-Brasil roots, the certificate's revocation (CRL), the CNPJ inside the certificate and that the
   company is ATIVA at the Receita Federal. Credential issued for 90 days.
4. `POST /v1/agents/{id}/renew` ($0.10) every 90 days; `POST /v1/agents/{id}/revoke` (free, e-CNPJ-signed) at once.

Agent keys: `evm` (wallet address, EIP-191), `web-bot-auth` (Ed25519, RFC 9421) or `erc8004`
(`eip155:<chainId>:<registry>:<agentId>`, an [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) agent whose
on-chain `agentWallet` signs; re-read daily, a wallet change suspends the credential).

Mandate example (validated by `/.well-known/kya-mandate.schema.json`; free-form fields are kept, listed as not evaluated):

```json
{ "actions": ["quote", "order", "pay"],
  "max_per_operation": { "amount": 5000, "currency": "BRL" },
  "max_per_day": { "amount": 20000, "currency": "BRL" },
  "currencies": ["BRL"], "counterparties": ["12345678000190", "*.beta.com.br"],
  "valid_until": "2027-01-01T00:00:00Z" }
```

The npm package signs the challenge for you (`signChallengeWithEvmKey`, `signChallengeWithEd25519`,
`signWithECnpj` from an A1 certificate in PEM); see [packages/agent-tools](packages/agent-tools/README.md).

## Tools and prices

| Tool | HTTP | USDC |
| --- | --- | --- |
| `kya_about`, `kya_prove`, `kya_renew_prove`, `kya_revoke`, `kya_revocations` | `POST /v1/agents/{id}/prove`, `/renew/prove`, `/revoke`; `GET /v1/revocations` | free |
| `kya_verify` | `GET /v1/agents/{id}`, `GET /v1/agents/by-key` | free, 50/day per IP |
| `kya_verify_paid` | `GET /v1/agents/{id}/verified` | 0.01 |
| `kya_check_action` | `GET /v1/agents/{id}/allowed` | 0.01 |
| `kya_register_act` | `POST /v1/agents/{id}/acts` | 0.02 |
| `kya_act`, `kya_act_text`, `kya_acts_export` | `GET /v1/acts/{act_id}`; `POST /v1/agents/{id}/acts/text`, `/acts/export` | free |
| `kya_renew` | `POST /v1/agents/{id}/renew` | 0.10 |
| `kya_register` | `POST /v1/agents` | 0.50 |

Discovery: `/docs` (Swagger UI), `/llms.txt`, `/openapi.json`, `/server.json`, `/.well-known/kya.json` (signing keys, active and
retired), `/.well-known/kya-mandate.schema.json`, `/.well-known/x402`, `/status`, `/terms`.
Verifier for any signed document: `POST /v1/verify`.

## What the credential looks like

```json
{ "credential_id": "6d0b…", "version": 1,
  "agent": { "kind": "evm", "id": "0x7099…" },
  "principal": { "cnpj": "11222333000181", "legal_name": "ACME LTDA", "registration_status": "ATIVA" },
  "authorized_by": { "method": "icp-brasil-e-cnpj", "certificate_sha256": "3b7a…", "certificate_subject": "CN=ACME LTDA:11222333000181, …", "signed_at": "…" },
  "mandate": { "…": "…" },
  "kyb_snapshot": { "risk_level": "low", "active_sanctions": 0, "forced_labor": false, "checked_at": "…" },
  "status": "active", "issued_at": "…", "expires_at": "…",
  "verify_url": "https://kya-br-agents.marcelfons.workers.dev/v1/agents/6d0b…",
  "attestation": { "algorithm": "ed25519", "key_id": "35bb864a2e87c8fd", "sha256": "…", "signed_at": "…", "signature": "…" } }
```

The signature covers the credential as issued. Suspension (company not ATIVA, certificate on hold),
revocation (by the company, or because its e-CNPJ was revoked at the AC) and expiry are
reported live at `verify_url` and in `/v1/revocations`. Only legal-entity data is processed: no CPF, no
name of the certificate holder, only the certificate hash.

## Architecture

```
agent / verifier ──x402──▶ kya-br-agents (Cloudflare Worker: Hono HTTP + MCP Durable Object)
                              │  D1 (agents, challenges, events, call_log)   KV (cache, limits, ICP anchors)
                              │  cron 03:17 UTC: daily review (e-CNPJ CRL, registration status)
                              ├──Service Binding──▶ kyb-br-agents (KYB Brasil, closed, optional)
                              └──or HTTPS──▶ BrasilAPI / CNPJ.ws (Receita open data, when there is no KYB)
```

The issuer acts on one company fact only, the registration status (D-15), and its source is configurable
(`REGISTRATION_SOURCE`, D-17): KYB Brasil when it is configured (a separate product, reached through a
Cloudflare Service Binding, never public HTTP or x402; client in `apps/worker/src/kyb.ts`), otherwise the
Receita's open data through BrasilAPI with CNPJ.ws as fallback (`apps/worker/src/registration.ts`). With
KYB, its risk screen at issuance is carried in `kyb_snapshot` for information; without it, `null`. CRLs are fetched from the URLs in each certificate
(`apps/worker/src/revocation.ts`).

| Path | What |
| --- | --- |
| `packages/core` | Pure logic: CNPJ, mandate schema and checks, challenge, agent signatures (EVM, Ed25519, ERC-8004 wallet resolution), e-CNPJ CMS + ICP-Brasil chain validation, credential build and signing, attestation. |
| `packages/agent-tools` | npm `@kya-brasil/agent-tools`: client with x402, signing helpers, local attestation check, adapters for OpenAI, Vercel AI, LangChain and Anthropic. |
| `apps/worker` | The issuer: HTTP routes, MCP server, D1 store, KV limits, registration sources (KYB or public), CRL checks, daily review. |
| `infra` | Pulumi: KV, D1 + migrations, Worker, optional KYB service binding, cron. |
| `anchors` | ICP-Brasil trust anchors (PEM) uploaded to KV by the CD. No anchors, no issuance. |
| `docs` | Specification, test vectors, decisions, runbook. |

## Develop and deploy

```
pnpm install && pnpm typecheck && pnpm test
cd apps/worker && cp .dev.vars.example .dev.vars && pnpm dev      # no KYB needed: public registration sources
```

Push to `main` deploys: the CD creates the Pulumi stacks `dev` and `prod` from the GitHub environments of
the same name (`PULUMI_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `PAY_TO`; optional
`KYB_INTERNAL_KEY`, `INTERNAL_API_KEY`, `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET`), uploads the
anchors, runs the smoke test and publishes the MCP Registry entry when it changed. The signing key is
generated once per stack and kept in the encrypted stack config; rotations keep the old public key
published as retired. See [docs/RUNBOOK.md](docs/RUNBOOK.md) and [docs/DECISOES.md](docs/DECISOES.md).

## Run your own issuer

The code is MIT and needs nothing closed: fork it, set a Cloudflare account, a Pulumi token and a receiving
wallet, and push. Your issuer signs with its own key. Step by step: [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md).

**Code and service.** The MIT license covers this code. The hosted issuer at
`kya-br-agents.marcelfons.workers.dev` is a service with its own [terms](https://kya-br-agents.marcelfons.workers.dev/terms),
and the name KYA Brasil identifies it; a fork is a different issuer with a different key, and verifiers
choose which issuers they trust.

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [SECURITY.md](SECURITY.md)
(report vulnerabilities privately). Changes to the format are changes to the spec first; `/v1` fields are
only added, never renamed or removed.
