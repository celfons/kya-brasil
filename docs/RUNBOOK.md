# Runbook

## Segredos por ambiente (GitHub environments `dev` e `prod`)
`PULUMI_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `PAY_TO`, `KYB_INTERNAL_KEY`
(o `INTERNAL_API_KEY` do Worker KYB Brasil do mesmo ambiente). Opcionais: `INTERNAL_API_KEY`,
`CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`. Vars opcionais: `WORKER_NAME`, `KYB_WORKER_NAME`, `X402_NETWORK`,
`FACILITATOR_URL`, `ISSUER_URL`.

## Âncoras ICP-Brasil
O CD roda `scripts/icp-anchors.mjs --all` (todas as ACs credenciadas) e cai para só as raízes se o zip
falhar. Se o repositório do ITI estiver fora do ar, o KV mantém o valor anterior. Para carregar à mão a
partir de um arquivo: `KV_NAMESPACE_ID=... node scripts/icp-anchors.mjs --file bundle.pem`.
`GET /status` não mostra as âncoras; uma prova com âncoras ausentes responde 422 `CERTIFICATE_INVALID`
com a mensagem de que não há âncoras.

## Chave de assinatura
Gerada uma vez por stack pelo CD e guardada na config do Pulumi (`pulumi config refresh --force` a
restaura em cada deploy). Rotação: `node scripts/rotate-attest-key.mjs` imprime a chave nova e o JSON de
chaves aposentadas a colocar em `kya-br-agents:attestPreviousKeys`.

## Revisão diária
Cron `17 3 * * *` UTC chama `dailyReview`: até 500 credenciais ativas ou suspensas por execução, ordenadas
pela revisão mais antiga. O log do Worker mostra `daily review {"reviewed","suspended","reinstated","errors"}`.

## Teste local
`pnpm dev` com `.dev.vars` (ver `.dev.vars.example`). Para o KYB: `wrangler dev --port 8788` no repositório
do KYB Brasil e `KYB_URL=http://localhost:8788`.
