# Changelog

## 0.3.0

- Acts: `POST /v1/agents/{id}/acts` ($0.02, MCP `kya_register_act`) registers what the agent did, re-checks the mandate with everything registered today (daily ceilings across counterparties), records denied acts as evidence and returns a signed receipt; `GET /v1/acts/{act_id}`, act text for the optional agent signature, and the company's trail export signed with the e-CNPJ. `/allowed` now uses the registered total too (`spent_today_registered`). Spec section 13.

## 0.2.0

- ERC-8004 identities (read-only): agent kind `erc8004`, wallet resolved on chain (Base, Ethereum and their testnets by default; `EVM_RPC_URLS` to add chains) at registration, proof and daily review; credentials carry `agent.wallet`.
- Open source under MIT: LICENSE, SECURITY.md, CONTRIBUTING.md; specification `docs/SPEC.md` with test vectors.
- Examples fixed: `max_per_operation` and `max_per_day` are `{ amount, currency }`, as the schema says.
- npm package `@kya-brasil/agent-tools` (client, signing helpers, adapters) with a manual publish workflow.
- MCP server (streamable HTTP at `/mcp`, one Durable Object per session) with the same tools as the HTTP API and x402 inside the protocol; `/server.json` and `/icon.svg`; automatic publication to the MCP Registry from the prod CD; optional Glama claim at `/.well-known/glama.json`.

## 0.1.0 (phase 1, unreleased)

- Core: mandate schema and action checks, challenge text and agent signature verification (EIP-191, Ed25519), e-CNPJ CMS verification with chain validation against ICP-Brasil anchors, credential build and Ed25519 signing, attestation helpers.
- Worker: register (x402 $0.50), prove (free), verify (free, 50/day per IP) and verified ($0.01, signed receipt), allowed ($0.01, signed verdict), renew ($0.10) in two steps, revoke (free, e-CNPJ-signed), revocation list, verifier, well-known documents, OpenAPI, llms.txt, status; fiat channel under `/internal/v1/*`; daily cron review through KYB Brasil.
- KYB Brasil reached through a Cloudflare Service Binding (`KYB`) on its internal channel.
- Infra: Pulumi program (KV, D1 + migrations, Worker, service binding, cron), CI and CD workflows, ICP-Brasil anchors upload, smoke test.
