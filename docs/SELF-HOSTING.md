# Run your own issuer

The code is MIT: anyone can run a KYA issuer with its own signing key, on its own Cloudflare account.
Nothing closed is required. KYB Brasil is optional; without it the issuer reads the company's registration
status from the Receita Federal's open data through BrasilAPI, with CNPJ.ws as fallback (D-17).

Your issuer is a different issuer: its credentials are signed by your key and verified against your
`/.well-known/kya.json`. Verifiers decide which issuers they trust; the name "KYA Brasil" and the hosted
service at `kya-br-agents.marcelfons.workers.dev` identify this project's own issuer.

## What you need

| | |
| --- | --- |
| Cloudflare account | Workers (Durable Objects), D1, KV. The free plan is enough to start. |
| Pulumi account | State and encrypted config of the stack (free tier). |
| Receiving wallet | An EVM address for x402 payments (`PAY_TO`). Testnet first: Base Sepolia, `eip155:84532`. |
| ICP-Brasil anchors | `anchors/icp-brasil.pem` is in the repository; refresh it from the ITI repository (see `docs/RUNBOOK.md`). |
| Optional | A KYB Brasil Worker in the same account (`KYB_INTERNAL_KEY`), Coinbase CDP keys for the mainnet facilitator. |

## Local

```sh
pnpm install && pnpm typecheck && pnpm test
cd apps/worker && cp .dev.vars.example .dev.vars
node ../../scripts/gen-attest-key.mjs        # paste the private key into ATTEST_PRIVATE_KEY
# leave KYB_URL / KYB_INTERNAL_KEY empty: registration status comes from BrasilAPI / CNPJ.ws
npx wrangler d1 migrations apply kya-br --local
pnpm dev                                     # http://localhost:8787, /docs, /status
```

`GET /status` shows `registration_source` (`kyb` or `public`) and the signing key id.

## Cloud, with the included CD

1. Fork the repository. Create the GitHub environments `dev` and `prod`.
2. Secrets in each environment: `PULUMI_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN` (Workers, D1, KV edit),
   `CLOUDFLARE_ACCOUNT_ID`, `PAY_TO`. Optional: `KYB_INTERNAL_KEY`, `INTERNAL_API_KEY`, `CDP_API_KEY_ID`,
   `CDP_API_KEY_SECRET`.
3. Variables (optional): `WORKER_NAME` (pick your own, e.g. `kya-acme`), `ISSUER_URL` (your public URL, used
   inside credentials), `X402_NETWORK`, `FACILITATOR_URL`, `REGISTRATION_SOURCE` (`auto`, `kyb` or `public`).
4. Push to `main`. The CD creates the stacks, applies the D1 migrations, generates the signing key once per
   stack (kept in the encrypted Pulumi config), uploads the anchors and runs the smoke test.

Without the CD: `cd infra && pulumi stack init dev`, set the same values with `pulumi config set` (see
`infra/index.ts` for the names) and `pulumi up`.

## What your issuer attests

The same as this one (docs/SPEC.md): an agent key acts for a company within a mandate, the e-CNPJ that
authorized it is valid and not revoked (CRL checked daily), and the company is ATIVA at the Receita. It does
not assess the company's risk. Keep your signing key safe: rotate with `scripts/rotate-attest-key.mjs` and
keep retired public keys published so old credentials still verify.

## Limits of the public registration sources

BrasilAPI and CNPJ.ws mirror the Receita's open data, refreshed monthly; a status change can take weeks to
show. They rate-limit: the daily review checks up to 500 credentials per run, one call each. When neither
answers, issuance fails with `REGISTRY_UNAVAILABLE` (502, never charged) and the review leaves the
credential unchanged that day.
