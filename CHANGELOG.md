# Changelog

## 0.1.0 (phase 1, unreleased)

- Core: mandate schema and action checks, challenge text and agent signature verification (EIP-191, Ed25519), e-CNPJ CMS verification with chain validation against ICP-Brasil anchors, credential build and Ed25519 signing, attestation helpers.
- Worker: register (x402 $0.50), prove (free), verify (free, 50/day per IP) and verified ($0.01, signed receipt), allowed ($0.01, signed verdict), renew ($0.10) in two steps, revoke (free, e-CNPJ-signed), revocation list, verifier, well-known documents, OpenAPI, llms.txt, status; fiat channel under `/internal/v1/*`; daily cron review through KYB Brasil.
- KYB Brasil reached through a Cloudflare Service Binding (`KYB`) on its internal channel.
- Infra: Pulumi program (KV, D1 + migrations, Worker, service binding, cron), CI and CD workflows, ICP-Brasil anchors upload, smoke test.
