# Runbook

## Segredos por ambiente (GitHub environments `dev` e `prod`)
`PULUMI_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `PAY_TO`. Opcionais:
`INTERNAL_API_KEY`, `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`. Vars opcionais: `WORKER_NAME`, `CNPJ_API_URL`
(fonte própria da situação cadastral no formato BrasilAPI, tentada antes da BrasilAPI e do CNPJ.ws, D-23),
`X402_NETWORK`, `FACILITATOR_URL`, `ISSUER_URL`.

## Âncoras ICP-Brasil
Fonte principal: `anchors/icp-brasil.pem`, um pacote PEM versionado no repositório com as raízes da
AC Raiz (v2, v5, v10, v11, v12) e, de preferência, as ACs intermediárias credenciadas (ACcompactado.zip).
Baixe de https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz num navegador (o site
usa certificado ICP-Brasil, que o Node do runner não reconhece), converta com
`openssl x509 -inform der -in arquivo.crt` quando vier em DER, concatene e faça commit. O CD envia
esse arquivo ao KV em cada deploy. Sem o arquivo, ele tenta baixar do ITI e só avisa se falhar; o KV
mantém o valor anterior. À mão: `KV_NAMESPACE_ID=... node scripts/icp-anchors.mjs --file anchors/icp-brasil.pem`.
`GET /status` não mostra as âncoras; uma prova com âncoras ausentes responde 422 `CERTIFICATE_INVALID`
com a mensagem de que não há âncoras.

## Chave de assinatura
Gerada uma vez por stack pelo CD e guardada na config do Pulumi (`pulumi config refresh --force` a
restaura em cada deploy). Rotação: `node scripts/rotate-attest-key.mjs` imprime a chave nova e o JSON de
chaves aposentadas a colocar em `kya-br-agents:attestPreviousKeys`.

## Revisão diária
Cron `17 3 * * *` UTC chama `dailyReview`: até 500 credenciais ativas ou suspensas por execução, ordenadas
pela revisão mais antiga: LCR do e-CNPJ (D-16) e situação cadastral (D-15). O log do Worker mostra
`daily review {"reviewed","suspended","reinstated","revoked","errors"}`.

## Teste local
`pnpm dev` com `.dev.vars` (ver `.dev.vars.example`). A situação cadastral vem da BrasilAPI / CNPJ.ws sem chave;
para testar uma fonte própria, `CNPJ_API_URL=http://localhost:3000/api/cnpj/v1/{cnpj}`.
