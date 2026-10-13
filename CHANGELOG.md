# Changelog

## 0.2.0

- Open source under MIT: LICENSE, SECURITY.md, CONTRIBUTING.md; specification `docs/SPEC.md` with test vectors.
- Examples fixed: `max_per_operation` and `max_per_day` are `{ amount, currency }`, as the schema says.
- npm package `@kya-brasil/agent-tools` (client, signing helpers, adapters) with a manual publish workflow.
- MCP server (streamable HTTP at `/mcp`, one Durable Object per session) with the same tools as the HTTP API and x402 inside the protocol; `/server.json` and `/icon.svg`; automatic publication to the MCP Registry from the prod CD; optional Glama claim at `/.well-known/glama.json`.

## 0.1.0 (phase 1, unreleased)

- Core: mandate schema and action checks, challenge text and agent signature verification (EIP-191, Ed25519), e-CNPJ CMS verification with chain validation against ICP-Brasil anchors, credential build and Ed25519 signing, attestation helpers.
- Worker: register (x402 $0.50), prove (free), verify (free, 50/day per IP) and verified ($0.01, signed receipt), allowed ($0.01, signed verdict), renew ($0.10) in two steps, revoke (free, e-CNPJ-signed), revocation list, verifier, well-known documents, OpenAPI, llms.txt, status; fiat channel under `/internal/v1/*`; daily cron review through KYB Brasil.
- KYB Brasil reached through a Cloudflare Service Binding (`KYB`) on its internal channel.
- Infra: Pulumi program (KV, D1 + migrations, Worker, service binding, cron), CI and CD workflows, ICP-Brasil anchors upload, smoke test.
