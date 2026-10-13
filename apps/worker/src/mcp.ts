import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { type X402AugmentedServer, type X402Config, withX402 } from "agents/x402";
import { z } from "zod";
import { KyaError } from "@kya-br/core";
import { signAnswer } from "./attest";
import { checkFreeTier, checkRegistrations } from "./cache";
import { logCall } from "./call-log";
import type { AppEnv } from "./env";
import { facilitatorConfig } from "./facilitator";
import { HOMEPAGE, SERVICE_DESCRIPTION, SERVICE_NAME, TOOLS, VERSION, type ToolName } from "./pricing";
import * as service from "./service";
import { Store } from "./store";

const AGENT = z.object({
  kind: z.enum(["evm", "web-bot-auth", "erc8004"]).describe("evm: an Ethereum-style wallet (EIP-191 signatures). web-bot-auth: an Ed25519 key (RFC 9421 / Web Bot Auth). erc8004: an agent registered in an ERC-8004 Identity Registry; its on-chain agentWallet signs."),
  id: z.string().min(20).max(160).describe("0x address for evm; base64url raw Ed25519 public key for web-bot-auth; eip155:<chainId>:<identityRegistry>:<agentId> for erc8004.")
});
const CNPJ = z.string().min(14).max(18).describe("The company's CNPJ, with or without punctuation.");
const ID = z.string().uuid().describe("credential_id returned by kya_register.");
const PROOF = {
  credential_id: ID,
  challenge_id: z.string().describe("challenge.id from kya_register (or kya_renew)."),
  agent_signature: z.string().describe("Signature of challenge.text by the agent key: EIP-191 personal_sign hex (evm) or raw Ed25519 base64url (web-bot-auth)."),
  ecnpj_signature: z.string().describe("CMS/PKCS#7 SignedData (detached, base64 DER) of challenge.text, signed with the company's e-CNPJ certificate.")
};

function toolResult(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value) }] };
}

/** `isError: true` makes the x402 wrapper skip settlement, so errors are never charged. */
function toolError(err: unknown) {
  const code = err instanceof KyaError ? err.code : "UPSTREAM_ERROR";
  const message = err instanceof Error ? err.message : String(err);
  if (!(err instanceof KyaError)) console.error("mcp tool failed", err);
  return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: code, message }) }] };
}

/** Payer/network from the verified payment payload the client sent in `_meta["x402/payment"]`. */
function paymentInfo(extra: unknown): { network?: string; payer?: string } {
  try {
    const meta = (extra as { _meta?: Record<string, unknown> })?._meta;
    const token = meta?.["x402/payment"];
    if (typeof token !== "string") return {};
    const payload = JSON.parse(atob(token)) as { accepted?: { network?: string }; payload?: { authorization?: { from?: string } } };
    return { network: payload.accepted?.network, payer: payload.payload?.authorization?.from };
  } catch {
    return {};
  }
}

/**
 * MCP server (streamable HTTP at /mcp). Each session is a Durable Object. Paid tools use the Agents
 * SDK x402 wrapper: an unpaid call gets isError + _meta["x402/error"]; the client pays and retries
 * with _meta["x402/payment"]; the wrapper verifies before and settles after the callback, only on success.
 */
export class KyaMcp extends McpAgent<AppEnv, unknown, { ip?: string }> {
  server!: McpServer & X402AugmentedServer;

  private x402Config(): X402Config {
    return { network: this.env.X402_NETWORK, recipient: this.env.PAY_TO, facilitator: facilitatorConfig(this.env) };
  }

  private origin() {
    return (this.env.ISSUER_URL ?? HOMEPAGE).replace(/\/$/, "");
  }

  private async logged<T>(tool: ToolName, paid: { network?: string; payer?: string } | null, fn: () => Promise<T>) {
    const t0 = Date.now();
    try {
      const value = await fn();
      await logCall(this.env, { transport: "http", tool, price_usd: TOOLS[tool].priceUsd, paid: !!paid, network: paid?.network ?? null, payer: paid?.payer ?? null, latency_ms: Date.now() - t0 });
      return toolResult(value);
    } catch (err) {
      const code = err instanceof KyaError ? err.code : "UPSTREAM_ERROR";
      await logCall(this.env, { transport: "http", tool, price_usd: 0, paid: false, latency_ms: Date.now() - t0, error_code: code });
      return toolError(err);
    }
  }

  async init() {
    const callerKey = `mcp:${this.props?.ip && this.props.ip !== "unknown" ? this.props.ip : this.name}`;
    const origin = this.origin();
    this.server = withX402(
      new McpServer({ name: SERVICE_NAME, title: SERVICE_NAME, version: VERSION, description: SERVICE_DESCRIPTION, websiteUrl: HOMEPAGE, icons: [{ src: `${HOMEPAGE}/icon.svg`, mimeType: "image/svg+xml", sizes: ["any"] }] }),
      this.x402Config()
    );
    const ro = { readOnlyHint: true, openWorldHint: true };

    // ---- paid ----
    this.server.paidTool(
      "kya_register", TOOLS.kya_register.description, TOOLS.kya_register.priceUsd,
      { agent: AGENT, cnpj: CNPJ, mandate: z.record(z.string(), z.unknown()).describe(`Mandate JSON validated by ${origin}/.well-known/kya-mandate.schema.json. Reserved fields: actions, max_per_operation, max_per_day, currencies, counterparties, valid_from, valid_until.`) },
      { openWorldHint: true },
      async (input, extra) =>
        this.logged("kya_register", paymentInfo(extra), async () => {
          const rl = await checkRegistrations(this.env, this.props?.ip ?? "unknown");
          if (!rl.allowed) throw new KyaError("RATE_LIMITED", `too many registrations today; retry in ${rl.retryAfter}s`);
          return service.register(this.env, origin, input as { agent: unknown; cnpj: unknown; mandate: unknown });
        })
    );
    this.server.paidTool(
      "kya_verify_paid", TOOLS.kya_verify_paid.description, TOOLS.kya_verify_paid.priceUsd, { credential_id: ID }, ro,
      async ({ credential_id }, extra) =>
        this.logged("kya_verify_paid", paymentInfo(extra), async () => {
          const v = await service.verify(this.env, credential_id);
          const out: Record<string, unknown> = { ...v, verification: { checked_at: new Date().toISOString(), checks: ["credential signature", "status", "expiry", "events"], paid: true } };
          const attestation = await signAnswer(this.env, out, origin);
          return attestation ? { ...out, attestation } : out;
        })
    );
    this.server.paidTool(
      "kya_check_action", TOOLS.kya_check_action.description, TOOLS.kya_check_action.priceUsd,
      {
        credential_id: ID,
        action: z.string().max(64).optional().describe("Action the agent wants to perform (e.g. pay, order, sign)."),
        amount: z.number().nonnegative().optional(),
        currency: z.string().max(12).optional().describe("BRL, USDC, ..."),
        counterparty: z.string().max(128).optional().describe("CNPJ, domain or wallet address of the other side."),
        spent_today: z.number().nonnegative().optional().describe("What this agent already spent today, if you track it (used for max_per_day).")
      },
      ro,
      async (i, extra) =>
        this.logged("kya_check_action", paymentInfo(extra), () =>
          service.allowed(this.env, origin, i.credential_id, { action: i.action, amount: i.amount?.toString(), currency: i.currency, counterparty: i.counterparty, spent_today: i.spent_today?.toString() })
        )
    );
    this.server.paidTool(
      "kya_register_act", TOOLS.kya_register_act.description, TOOLS.kya_register_act.priceUsd,
      {
        credential_id: ID,
        action: z.string().max(32).describe("What the agent did: pay, order, sign, quote..."),
        amount: z.number().nonnegative().optional(),
        currency: z.string().max(10).optional(),
        counterparty: z.string().max(128).optional().describe("Who accepted it: CNPJ, domain or wallet address."),
        reference: z.string().max(200).optional().describe("Order number, invoice, URL."),
        content_sha256: z.string().length(64).optional().describe("SHA-256 hex of the document; only the hash is stored."),
        registered_by: z.enum(["counterparty", "agent"]).optional(),
        registrant: z.string().max(128).optional(),
        agent_signature: z.string().max(400).optional().describe("Proof of origin: the agent's signature over the act text (kya_act_text)."),
        agent_request: z
          .object({
            method: z.string().max(10),
            url: z.string().max(2048),
            created: z.number().int(),
            expires: z.number().int(),
            content_sha256: z.string().length(64).optional(),
            signature: z.string().max(400)
          })
          .optional()
          .describe("Proof of origin: the agent's signed KYA request you received (KYA-Created, KYA-Expires, KYA-Content-SHA256, KYA-Signature, plus method and URL). Without a proof the act is kept but does not count toward the daily total.")
      },
      { openWorldHint: true },
      async (i, extra) => this.logged("kya_register_act", paymentInfo(extra), () => service.registerAct(this.env, origin, i.credential_id, i as Record<string, unknown>))
    );
    this.server.paidTool(
      "kya_renew", TOOLS.kya_renew.description, TOOLS.kya_renew.priceUsd, { credential_id: ID }, { openWorldHint: true },
      async ({ credential_id }, extra) => this.logged("kya_renew", paymentInfo(extra), () => service.renewChallenge(this.env, origin, credential_id))
    );

    // ---- free ----
    const limited = async () => {
      const rl = await checkFreeTier(this.env, callerKey);
      return rl.allowed ? null : toolError(new KyaError("RATE_LIMITED", `Free verification limit reached for today (retry in ${rl.retryAfter}s); kya_verify_paid has no limit.`));
    };
    this.server.registerTool(
      "kya_prove",
      { description: TOOLS.kya_prove.description, inputSchema: PROOF, annotations: { openWorldHint: true } },
      async (i) => this.logged("kya_prove", null, () => service.prove(this.env, origin, i.credential_id, i))
    );
    this.server.registerTool(
      "kya_verify",
      { description: TOOLS.kya_verify.description, inputSchema: { credential_id: ID.optional(), agent: AGENT.optional().describe("Alternative to credential_id: look up active credentials by agent key.") }, annotations: ro },
      async (i) =>
        (await limited()) ??
        this.logged("kya_verify", null, async () => {
          if (i.credential_id) return service.verify(this.env, i.credential_id);
          if (i.agent) return service.verifyByKey(this.env, i.agent.kind, i.agent.id);
          throw new KyaError("INVALID_INPUT", "give credential_id or agent");
        })
    );
    this.server.registerTool(
      "kya_renew_prove",
      { description: "Free. Second step of kya_renew: send both signatures of the renewal challenge; the credential is re-issued for 90 days if the e-CNPJ is not revoked and the company is still ATIVA.", inputSchema: PROOF, annotations: { openWorldHint: true } },
      async (i) => this.logged("kya_renew", null, () => service.renewProve(this.env, origin, i.credential_id, i))
    );
    this.server.registerTool(
      "kya_revoke",
      {
        description: TOOLS.kya_revoke.description,
        inputSchema: {
          credential_id: ID,
          signed_text: z.string().describe('Exactly "KYA Brasil: revoke <credential_id>" followed by a newline and a nonce of your choice.'),
          ecnpj_signature: z.string().describe("CMS/PKCS#7 SignedData (detached, base64 DER) of signed_text with the company's e-CNPJ."),
          reason: z.string().max(200).optional()
        },
        annotations: { destructiveHint: true, openWorldHint: true }
      },
      async (i) => this.logged("kya_revoke", null, () => service.revoke(this.env, i.credential_id, i))
    );
    this.server.registerTool(
      "kya_act",
      { description: TOOLS.kya_act.description, inputSchema: { act_id: z.string().uuid() }, annotations: { readOnlyHint: true, idempotentHint: true } },
      async ({ act_id }) => this.logged("kya_act", null, () => service.getAct(this.env, act_id))
    );
    this.server.registerTool(
      "kya_act_text",
      { description: "Free. The exact text an agent signs to show it intended an act (optional agent_signature of kya_register_act).", inputSchema: { credential_id: ID, action: z.string().max(32), amount: z.number().optional(), currency: z.string().max(10).optional(), counterparty: z.string().max(128).optional(), reference: z.string().max(200).optional(), content_sha256: z.string().length(64).optional() }, annotations: ro },
      async (i) => this.logged("kya_act", null, () => service.actTextFor(this.env, origin, i.credential_id, i as Record<string, unknown>))
    );
    this.server.registerTool(
      "kya_acts_export",
      { description: TOOLS.kya_acts_export.description, inputSchema: { credential_id: ID, signed_text: z.string().describe('Exactly "KYA Brasil: acts <credential_id>" followed by a newline and a nonce.'), ecnpj_signature: z.string(), since: z.string().datetime().optional() }, annotations: ro },
      async (i) => this.logged("kya_acts_export", null, () => service.exportActs(this.env, i.credential_id, i))
    );
    this.server.registerTool(
      "kya_revocations",
      { description: "Free. Credentials revoked since a date (default: last 30 days), for verifiers that cache credentials.", inputSchema: { since: z.string().datetime().optional() }, annotations: { readOnlyHint: true, idempotentHint: true } },
      async ({ since }) => {
        try {
          const from = since ?? new Date(Date.now() - 30 * 86400_000).toISOString();
          const revocations = await new Store(this.env.DB).revocations(from);
          return toolResult({ since: from, count: revocations.length, revocations });
        } catch (err) {
          return toolError(err);
        }
      }
    );
    this.server.registerTool(
      "kya_about",
      { description: "Free. What KYA Brasil is, how the credential flow works, prices, and where the schemas and signing keys are.", inputSchema: {}, annotations: { readOnlyHint: true, idempotentHint: true } },
      async () =>
        toolResult({
          service: SERVICE_NAME, version: VERSION, description: SERVICE_DESCRIPTION,
          flow: ["kya_register (paid) returns a challenge", "the agent signs it with its key, the company with its e-CNPJ", "kya_prove (free) issues the credential", "anyone calls kya_verify (free) or kya_check_action (paid) before accepting the agent's action", "whoever accepted the action calls kya_register_act (paid): mandate re-checked with today's registered acts, signed receipt", "kya_renew every 90 days, kya_revoke at once"],
          prices_usd: Object.fromEntries(Object.entries(TOOLS).map(([k, t]) => [k, t.priceUsd])),
          mandate_schema: `${origin}/.well-known/kya-mandate.schema.json`, signing_keys: `${origin}/.well-known/kya.json`, http_api: `${origin}/openapi.json`, llms: `${origin}/llms.txt`, terms: `${origin}/terms`
        })
    );
  }
}
