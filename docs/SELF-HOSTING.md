# Run your own issuer

The code is MIT: anyone can run a KYA issuer with its own signing key, on its own Cloudflare account.
Nothing closed, paid or keyed is required. The issuer reads the company's registration status from the
Receita Federal's open data through BrasilAPI, with CNPJ.ws as fallback (D-23). To depend on neither, run
your own source in the BrasilAPI format (a self-hosted BrasilAPI, or an import of the Receita dataset) and
set `CNPJ_API_URL` to it, e.g. `https://cnpj.example/api/cnpj/v1/{cnpj}`; it is tried first.
The check is optional (`REGISTRATION_CHECK=off`) and never blocks: when no source answers, the credential
is issued as `UNVERIFIED` with a warning in the response, and the daily review checks again (D-24).

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
| Optional | Your own CNPJ source (`CNPJ_API_URL`), Coinbase CDP keys for the mainnet facilitator. |

## Local

```sh
pnpm install && pnpm typecheck && pnpm test
cd apps/worker && cp .dev.vars.example .dev.vars
node ../../scripts/gen-attest-key.mjs        # paste the private key into ATTEST_PRIVATE_KEY
# leave CNPJ_API_URL empty: registration status comes from BrasilAPI / CNPJ.ws
npx wrangler d1 migrations apply kya-br --local
pnpm dev                                     # http://localhost:8787, /docs, /status
```

`GET /status` shows `registration_sources` (in the order they are tried) and the signing key id.

## Container (evaluation and integration)

The same runtime as production (`workerd`, through `wrangler dev`) with D1, KV and the Durable Object
emulated inside the container and persisted in a volume. No Cloudflare account, no API keys, no Coinbase keys:
registration status comes from the Receita's open data, payments stay on Base Sepolia, the ICP-Brasil
anchors are the bundle from the repository, and the signing key is generated once into the volume.

```sh
docker compose up --build          # http://localhost:8787  (/docs, /status, /mcp)
curl localhost:8787/status         # anchors: 180, registration_sources: [brasilapi, cnpjws], attestation_key: ...
curl -X POST localhost:8787/__scheduled   # run the daily review by hand
```

Variables are listed in `docker-compose.yml` (`PAY_TO`, `ISSUER_URL`, `X402_NETWORK`,
optional `CNPJ_API_URL`, `INTERNAL_API_KEY`, `CDP_API_KEY_ID`/`CDP_API_KEY_SECRET`). Set
`ISSUER_URL` to the public address before exposing the container: it is written into every credential.
This is not a production deployment: the state is a single SQLite file, there is no rollback, no edge, and
`wrangler dev` is a development server. For production use the cloud path below.

## Cloud, with the included CD

1. Fork the repository. Create the GitHub environments `dev` and `prod`.
2. Secrets in each environment: `PULUMI_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN` (Workers, D1, KV edit),
   `CLOUDFLARE_ACCOUNT_ID`, `PAY_TO`. Optional: `INTERNAL_API_KEY`, `CDP_API_KEY_ID`,
   `CDP_API_KEY_SECRET`.
3. Variables (optional): `WORKER_NAME` (pick your own, e.g. `kya-acme`), `ISSUER_URL` (your public URL, used
   inside credentials), `X402_NETWORK`, `FACILITATOR_URL`, `CNPJ_API_URL` (own registration source).
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
