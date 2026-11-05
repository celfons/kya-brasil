# Runbook

## Secrets per environment (GitHub environment `prod`; `dev` was removed from CD)
`PULUMI_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `PAY_TO`. Optional:
`INTERNAL_API_KEY`, `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`. Optional vars: `WORKER_NAME`, `CNPJ_API_URL`
(your own source for registration status in BrasilAPI format, tried before BrasilAPI and CNPJ.ws, D-23),
`REGISTRATION_CHECK` (`off` turns off the registration status check; a failure never blocks, it becomes a warning, D-24),
`X402_NETWORK`, `FACILITATOR_URL`, `ISSUER_URL`.

## ICP-Brasil anchors
Main source: `anchors/icp-brasil.pem`, a PEM bundle versioned in the repository with the roots of the
AC Raiz (v2, v5, v10, v11, v12) and, preferably, the accredited intermediate CAs (ACcompactado.zip).
Download from https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz in a browser (the site
uses an ICP-Brasil certificate, which the runner's Node does not recognize), convert with
`openssl x509 -inform der -in arquivo.crt` when it comes in DER, concatenate and commit. CD sends
this file to KV on every deploy. Without the file, it tries to download from ITI and only warns if that fails; KV
keeps the previous value. By hand: `KV_NAMESPACE_ID=... node scripts/icp-anchors.mjs --file anchors/icp-brasil.pem`.
`GET /status` does not show the anchors; a proof with missing anchors returns 422 `CERTIFICATE_INVALID`
with a message saying there are no anchors.

## Signing key
Generated once per stack by CD and stored in the Pulumi config (`pulumi config refresh --force`
restores it on every deploy). Rotation: `node scripts/rotate-attest-key.mjs` prints the new key and the JSON of
retired keys to put in `kya-br-agents:attestPreviousKeys`.

## Daily review
Cron `17 3 * * *` UTC calls `dailyReview`: up to 500 active or suspended credentials per run, ordered
by oldest review: e-CNPJ CRL (D-16) and registration status (D-15). The Worker log shows
`daily review {"reviewed","suspended","reinstated","revoked","errors"}`.

## Local testing
`pnpm dev` with `.dev.vars` (see `.dev.vars.example`). Registration status comes from BrasilAPI / CNPJ.ws with no key;
to test your own source, `CNPJ_API_URL=http://localhost:3000/api/cnpj/v1/{cnpj}`.
