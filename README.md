# KYA Brasil

Know-your-agent credentials for Brazil. A company proves with its **e-CNPJ** (ICP-Brasil certificate)
that an AI agent key (EVM wallet or Web Bot Auth Ed25519 key) acts on its behalf, within a declared
**mandate**. [KYB Brasil](https://kyb-br-agents.marcelfons.workers.dev) checks the company before
issuance and every day after. Credentials are Ed25519-signed JSON, verifiable at a stable URL and
revocable at once. Paid per call with x402 (USDC on Base); verification is free up to 50/day per IP.

Separate product from KYB Brasil, separate repository and Worker. The two talk through a Cloudflare
Service Binding (Worker to Worker, never public HTTP, never x402).

## Journey

1. `POST /v1/agents` ($0.50) with `{agent: {kind, id}, cnpj, mandate}` returns a one-time challenge.
2. The agent signs the challenge with its key (EIP-191 or Ed25519); the company signs it with its e-CNPJ (CMS/PKCS#7, detached).
3. `POST /v1/agents/{id}/prove` (free) validates both signatures, the certificate chain against the
   ICP-Brasil roots, the CNPJ inside the certificate, and asks KYB Brasil to clear the company. Then it issues the credential (90 days).
4. Anyone verifies it: `GET /v1/agents/{id}` (free, 50/day) or `/verified` ($0.01, signed receipt, no limit);
   `GET /v1/agents/{id}/allowed?action=pay&amount=80&currency=USDC&counterparty=<cnpj>` ($0.01) answers with a signed verdict.
5. `POST /v1/agents/{id}/renew` ($0.10) re-runs the proof for 90 more days; `POST /v1/agents/{id}/revoke` (free, e-CNPJ-signed) revokes at once.

Discovery for agents: `/llms.txt`, `/openapi.json`, `/.well-known/kya.json` (signing keys),
`/.well-known/kya-mandate.schema.json`, `/v1/revocations`, `/status`.

## Layout

| Path | What |
| --- | --- |
| `packages/core` | Pure logic, no Cloudflare types: CNPJ, mandate schema and checks, challenges, agent signatures, e-CNPJ (CMS + ICP-Brasil chain), credential build/sign, attestation. |
| `apps/worker` | Cloudflare Worker: Hono routes, x402 middleware, D1 store, KV cache and limits, KYB client over the service binding, daily cron review. |
| `infra` | Pulumi: KV, D1 + migrations, Worker with bindings and secrets, cron trigger. |
| `scripts` | Signing key generation and rotation, ICP-Brasil anchors upload, smoke test. |
| `.github/workflows` | CI (typecheck, tests, bundle) and CD (Pulumi up per stack, anchors, smoke, rollback). |

## Develop

```
pnpm install
pnpm typecheck && pnpm test
cd apps/worker && cp .dev.vars.example .dev.vars   # PAY_TO, ATTEST_PRIVATE_KEY, KYB_INTERNAL_KEY, KYB_URL, ICP_ANCHORS_PEM
pnpm dev
```

Locally the KYB Worker is reached over `KYB_URL` (a `wrangler dev` of KYB Brasil); in the cloud the
`KYB` service binding replaces it. `node scripts/gen-attest-key.mjs` prints a signing key.

## Deploy

Push to `main`. The CD creates the Pulumi stacks `dev` and `prod` from the GitHub environments of the
same name. Required secrets: `PULUMI_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`,
`PAY_TO`, `KYB_INTERNAL_KEY` (the `INTERNAL_API_KEY` of the KYB Brasil Worker). Optional:
`INTERNAL_API_KEY` (fiat channel), `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` (mainnet facilitator).

## Rules

- Legal entities only. No CPF is stored or returned; the signer of the e-CNPJ is recorded by certificate hash.
- Errors are never charged. Fields inside `/v1` are only added, never renamed or removed.
- No anchors in KV (`icp:anchors`) means no issuance: the issuer fails closed.
