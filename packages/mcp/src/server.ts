/**
 * KYA Brasil as a local MCP server. Three kinds of tools:
 *   - offline: run here, with @kya-brasil/core (mandate checks, delegation chains), no network;
 *   - issuer, free: read the issuer's public API (live status, revocations, signing links);
 *   - issuer, paid: signed verdicts, paid per call with x402 when KYA_PRIVATE_KEY holds a wallet with USDC on Base.
 * Nothing needs a key to start: without one the paid tools answer with PAYMENT_REQUIRED and the price.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type ActionQuery, type Mandate, KyaError, checkAction, checkDelegatedAction, decodeDelegationHeader, validateMandate, verifyDelegationChain } from "@kya-brasil/core";
import { type Credential, type KyaClient, createKyaClient, verifyCredentialOffline } from "@kya-brasil/agent-tools";

export const SERVER_NAME = "KYA Brasil";
export const SERVER_VERSION = "0.1.0";
export const DEFAULT_ISSUER = "https://kya-br-agents.marcelfons.workers.dev";

export interface KyaMcpOptions {
  /** Issuer origin; KYA_BASE_URL, else the reference issuer. */
  baseUrl?: string;
  /** Wallet key that pays the paid tools (x402, USDC on Base); KYA_PRIVATE_KEY. */
  privateKey?: `0x${string}`;
  fetch?: typeof fetch;
}

const ID = z.string().uuid().describe("The agent's credential_id (the agent sends it with its request, e.g. in the KYA-Credential header).");
const AGENT = z.object({
  kind: z.enum(["evm", "web-bot-auth", "erc8004"]).describe("evm: Ethereum-style wallet; web-bot-auth: Ed25519 key; erc8004: on-chain agent."),
  id: z.string().min(20).max(160).describe("0x address, base64url Ed25519 public key, or eip155:<chainId>:<registry>:<agentId>.")
});
const MANDATE = z.record(z.string(), z.unknown()).describe("A KYA mandate: actions, max_per_operation, max_per_day, currencies, counterparties, payment_instruments, valid_from, valid_until, delegation.");
const ACTION = {
  action: z.string().max(64).optional().describe("What the agent wants to do, lowercase (order, pay, quote, sign, ...)."),
  amount: z.number().nonnegative().optional().describe("Amount of this operation."),
  currency: z.string().max(12).optional().describe("BRL, USDC, ..."),
  counterparty: z.string().max(128).optional().describe("Your CNPJ, domain or wallet address (the other side of the operation)."),
  spent_today: z.number().nonnegative().optional().describe("What this agent already spent today, if you track it; needed for max_per_day (the issuer keeps no record of acts)."),
  payment_network: z.string().max(32).optional().describe("Payment network of this operation: visa, mastercard, elo, pix, ..."),
  payment_ref_sha256: z.string().regex(/^[0-9a-fA-F]{64}$/).optional().describe("SHA-256 hex of the payment token reference or PAR used, never a card number.")
};

type ActionInput = { action?: string; amount?: number; currency?: string; counterparty?: string; spent_today?: number; payment_network?: string; payment_ref_sha256?: string };
const toQuery = (i: ActionInput): ActionQuery => ({ action: i.action, amount: i.amount, currency: i.currency, counterparty: i.counterparty, spent_today: i.spent_today, payment_network: i.payment_network, payment_ref_sha256: i.payment_ref_sha256 });

function ok(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

function fail(err: unknown) {
  const code = err instanceof KyaError ? err.code : (err as { code?: string })?.code ?? "ERROR";
  const message = err instanceof Error ? err.message : String(err);
  return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: code, message }) }] };
}

const run = async (fn: () => Promise<unknown> | unknown) => {
  try {
    return ok(await fn());
  } catch (e) {
    return fail(e);
  }
};

export function createKyaMcpServer(opts: KyaMcpOptions = {}): { server: McpServer; client: KyaClient } {
  const baseUrl = (opts.baseUrl ?? DEFAULT_ISSUER).replace(/\/$/, "");
  const client = createKyaClient({ baseUrl, privateKey: opts.privateKey, fetch: opts.fetch });
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });
  const readOnlyOffline = { readOnlyHint: true, idempotentHint: true, openWorldHint: false };
  const readOnlyIssuer = { readOnlyHint: true, openWorldHint: true };

  // ---- issuer, free -------------------------------------------------------------------------------

  server.registerTool(
    "kya_verify",
    {
      title: "Verify an agent's credential",
      description:
        "Free. Who answers for this AI agent? Looks up the agent's KYA Brasil credential at the issuer and returns the principal (a Brazilian company with CNPJ and name, or a person verified by e-CPF with nothing personal), the mandate, the live status (active, suspended, revoked, expired) and its history. Give credential_id, or the agent key to find its active credentials. Use it before trusting an order, payment or signature that comes from an agent.",
      inputSchema: { credential_id: ID.optional(), agent: AGENT.optional().describe("Alternative to credential_id: the agent's key.") },
      annotations: readOnlyIssuer
    },
    async (i) =>
      run(() => {
        if (i.credential_id) return client.verify(i.credential_id);
        if (i.agent) return client.verifyByKey(i.agent);
        throw new KyaError("INVALID_INPUT", "give credential_id or agent");
      })
  );

  server.registerTool(
    "kya_revocations",
    {
      title: "List revoked credentials",
      description: "Free. Credentials the issuer revoked since a date (default: the last 30 days). For verifiers that cache credentials and want to drop revoked ones.",
      inputSchema: { since: z.string().datetime().optional().describe("ISO 8601 date-time; default 30 days ago.") },
      annotations: readOnlyIssuer
    },
    async (i) => run(() => client.revocations(i.since))
  );

  server.registerTool(
    "kya_sign_link",
    {
      title: "Signing link for the certificate holder",
      description:
        "Free. The link to send to whoever holds the e-CNPJ or e-CPF (owner, accountant, the person) so they see what is being authorized and sign in the browser. Use after a registration: give credential_id and challenge_id, and the agent's signature of the challenge so the holder only signs with the certificate.",
      inputSchema: { credential_id: ID, challenge_id: z.string().min(1).describe("challenge.id from the registration or renewal."), agent_signature: z.string().max(600).optional().describe("The agent key's signature of challenge.text.") },
      annotations: readOnlyIssuer
    },
    async (i) => run(() => client.signLink(i.credential_id, { challenge_id: i.challenge_id, agent_signature: i.agent_signature }))
  );

  // ---- issuer, paid -------------------------------------------------------------------------------

  server.registerTool(
    "kya_check_action",
    {
      title: "Signed verdict for an action (paid)",
      description:
        "$0.01 (x402, USDC on Base; set KYA_PRIVATE_KEY). May this agent perform this action under its mandate, and is its credential active right now? The issuer answers with a signed verdict that lists every rule it evaluated, usable as evidence in a dispute. For a free, unsigned answer use kya_check_mandate on the mandate from kya_verify.",
      inputSchema: { credential_id: ID, ...ACTION },
      annotations: readOnlyIssuer
    },
    async (i) => run(() => client.allowed(i.credential_id, toQuery(i)))
  );

  server.registerTool(
    "kya_verify_paid",
    {
      title: "Verify with a signed receipt (paid)",
      description: "$0.01 (x402, USDC on Base; set KYA_PRIVATE_KEY). Same answer as kya_verify, without the free daily limit, plus a signed receipt of the verification.",
      inputSchema: { credential_id: ID },
      annotations: readOnlyIssuer
    },
    async (i) => run(() => client.verified(i.credential_id))
  );

  // ---- offline ------------------------------------------------------------------------------------

  server.registerTool(
    "kya_check_mandate",
    {
      title: "Check an action against a mandate (offline)",
      description:
        "Free and offline. Evaluates an intended action against a KYA mandate (the credential's mandate from kya_verify, or one you are drafting) and lists every rule with its result: action, ceilings per operation and per day, currency, counterparty (with *.domain wildcards), payment instrument, validity window. Nothing is sent anywhere.",
      inputSchema: { mandate: MANDATE, ...ACTION },
      annotations: readOnlyOffline
    },
    async (i) => run(() => checkAction(validateMandate(i.mandate), toQuery(i)))
  );

  server.registerTool(
    "kya_validate_mandate",
    {
      title: "Validate a mandate (offline)",
      description:
        "Free and offline. Checks a mandate against the KYA schema before registering an agent with it, and returns it normalized (actions deduplicated, counterparties and payment instruments normalized). Refuses card numbers and malformed fields with the reason.",
      inputSchema: { mandate: MANDATE },
      annotations: readOnlyOffline
    },
    async (i) => run(() => ({ valid: true, mandate: validateMandate(i.mandate) }))
  );

  server.registerTool(
    "kya_verify_credential_offline",
    {
      title: "Verify a credential's signature (offline)",
      description:
        "Free. Checks a credential document you already hold: the issuer's Ed25519 signature (key from the issuer's /.well-known/kya.json, fetched once) and the expiry. It cannot see a revocation made after issuance (live_status is unknown); use kya_verify for the live status.",
      inputSchema: { credential: z.record(z.string(), z.unknown()).describe("The full credential JSON, including its attestation.") },
      annotations: { readOnlyHint: true, openWorldHint: true }
    },
    async (i) => run(() => verifyCredentialOffline(i.credential as unknown as Credential, { baseUrl, fetch: opts.fetch }))
  );

  server.registerTool(
    "kya_verify_delegation",
    {
      title: "Verify a sub-agent's delegation chain (offline)",
      description:
        "Free and offline. A sub-agent acts under a delegation chain signed by the credential's agent (KYA-Delegation header). Checks every link (signatures, depth, lifetime, each mandate contained in the one above) against the credential, returns the key that must sign the sub-agent's requests, and, when an action is given, evaluates it on every level: allowed only if all of them allow it.",
      inputSchema: {
        credential: z.record(z.string(), z.unknown()).describe("The credential (credential_id, agent, mandate, expires_at), e.g. the `credential` from kya_verify."),
        chain: z.union([z.string(), z.array(z.record(z.string(), z.unknown()))]).describe("The KYA-Delegation header value (base64url), or the chain as a JSON array."),
        ...ACTION
      },
      annotations: readOnlyOffline
    },
    async (i) =>
      run(async () => {
        const c = i.credential as { credential_id?: string; agent?: unknown; mandate?: unknown; expires_at?: string };
        if (!c.credential_id || !c.agent || !c.mandate || !c.expires_at) throw new KyaError("INVALID_INPUT", "credential must have credential_id, agent, mandate and expires_at");
        const chain = typeof i.chain === "string" ? decodeDelegationHeader(i.chain) : i.chain;
        const r = await verifyDelegationChain({ credential: { credential_id: c.credential_id, agent: c.agent as never, mandate: c.mandate as Mandate, expires_at: c.expires_at }, chain });
        if (!r.ok || (i.action === undefined && i.amount === undefined)) return r;
        return { ...r, action: checkDelegatedAction(r.mandates, toQuery(i)) };
      })
  );

  server.registerTool(
    "kya_about",
    {
      title: "About KYA Brasil",
      description: "Free and offline. What KYA Brasil is, how an agent gets a credential, which tools to use as a verifier, and where the specification and the issuer's keys are.",
      inputSchema: {},
      annotations: readOnlyOffline
    },
    async () =>
      ok({
        name: SERVER_NAME,
        version: SERVER_VERSION,
        what: "Know-your-agent backed by ICP-Brasil: a Brazilian company (e-CNPJ) or person (e-CPF) signs that an AI agent key acts for them within a mandate. The issuer checks the certificate chain, its revocation and the company's registration, and issues an Ed25519-signed credential.",
        verifier_flow: ["kya_verify: who answers for the agent, its mandate and live status", "kya_check_mandate (free, offline) or kya_check_action (paid, signed) before accepting the action", "kya_verify_delegation when a sub-agent presents a delegation chain"],
        issuer: baseUrl,
        paid_tools: opts.privateKey ? "enabled (KYA_PRIVATE_KEY set)" : "need KYA_PRIVATE_KEY (wallet with USDC on Base); the free and offline tools work without it",
        spec: "https://github.com/celfons/kya-brasil/blob/main/docs/SPEC.md",
        signing_keys: `${baseUrl}/.well-known/kya.json`,
        mandate_schema: `${baseUrl}/.well-known/kya-mandate.schema.json`
      })
  );

  return { server, client };
}
