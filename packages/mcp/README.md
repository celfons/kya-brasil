# @kya-brasil/mcp

KYA Brasil as a **local MCP server** (stdio). Ask, from Claude Desktop, Cursor or any MCP client, who answers for an AI
agent (a Brazilian company with its e-CNPJ, or a person with their e-CPF), what its mandate allows, and whether a
sub-agent's delegation chain holds. The free and offline tools need no key.

```json
{
  "mcpServers": {
    "kya-brasil": { "command": "npx", "args": ["-y", "@kya-brasil/mcp"] }
  }
}
```

The same tools are also served remotely at `https://kya-br-agents.marcelfons.workers.dev/mcp` (streamable HTTP). This
package runs on your machine instead: the offline tools never leave it, and the issuer is only read for live data.

## Tools

| Tool | Where | Price |
| --- | --- | --- |
| `kya_verify` | issuer | free: principal, mandate, live status and history of a credential (by id or agent key) |
| `kya_revocations` | issuer | free: credentials revoked since a date |
| `kya_sign_link` | issuer | free: the link the certificate holder opens to sign |
| `kya_check_action` | issuer | $0.01: signed verdict for an action under the mandate |
| `kya_verify_paid` | issuer | $0.01: `kya_verify` with a signed receipt, no daily limit |
| `kya_check_mandate` | offline | free: evaluate an action against a mandate, rule by rule |
| `kya_validate_mandate` | offline | free: validate and normalize a mandate before registering |
| `kya_verify_credential_offline` | offline (fetches the issuer's public key once) | free: signature and expiry of a credential you hold |
| `kya_verify_delegation` | offline | free: verify a sub-agent's delegation chain and evaluate the action on every level |
| `kya_about` | offline | free: what KYA Brasil is and how to use it |

## Configuration

| Variable | |
| --- | --- |
| `KYA_BASE_URL` | Issuer origin. Default: the reference issuer. Point it at your own issuer if you run one. |
| `KYA_PRIVATE_KEY` | Optional `0x` key of a wallet with USDC on Base, to pay the paid tools (x402). Without it they answer `PAYMENT_REQUIRED` with the price. |

## Build from the repository

```sh
pnpm install --frozen-lockfile --filter @kya-brasil/mcp...
pnpm --filter @kya-brasil/mcp build      # one self-contained file: packages/mcp/dist/index.js
node packages/mcp/dist/index.js          # speaks MCP on stdin/stdout
```

Specification: [docs/SPEC.md](https://github.com/celfons/kya-brasil/blob/main/docs/SPEC.md). License: MIT.
