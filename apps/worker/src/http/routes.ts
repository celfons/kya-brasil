import { HTTPFacilitatorClient } from "@x402/core/server";
import { registerExactEvmScheme } from "@x402/evm/exact/server";
import { bazaarResourceServerExtension, declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import { Hono, type Context } from "hono";
import { KyaError } from "@kya-br/core";
import { publishedKeys, signAnswer, verifyAnswer } from "../attest";
import { checkFreeTier, checkRegistrations, type LimitResult } from "../cache";
import { attachSettlement, decodeSettlementHeader, logCall } from "../call-log";
import type { AppEnv } from "../env";
import { facilitatorConfig } from "../facilitator";
import { SERVICE_DESCRIPTION, SERVICE_NAME, SERVICE_TAGS, TOOLS, VERSION, type ToolName } from "../pricing";
import * as service from "../service";
import { Store } from "../store";
import { llmsTxt, mandateSchema, openapiJson, termsText } from "./static";

type Vars = { callLogId: number | null };
type Ctx = Context<{ Bindings: AppEnv; Variables: Vars }>;

const ipOf = (c: Ctx) => c.req.header("cf-connecting-ip") ?? "unknown";
const originOf = (c: Ctx) => new URL(c.req.url).origin;
const idOf = (c: Ctx) => c.req.param("id") ?? "";

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const STATUS: Record<string, number> = {
  INVALID_INPUT: 400, INVALID_CNPJ: 400, NOT_FOUND: 404, CONFLICT: 409,
  CHALLENGE_FAILED: 422, CERTIFICATE_INVALID: 422, CNPJ_MISMATCH: 422, KYB_BLOCKED: 422,
  RATE_LIMITED: 429, KYB_UNAVAILABLE: 502, UPSTREAM_ERROR: 502
};

function errorResponse(err: unknown) {
  const code = err instanceof KyaError ? err.code : "UPSTREAM_ERROR";
  const message = err instanceof Error ? err.message : String(err);
  if (!(err instanceof KyaError)) console.error("unexpected error", err);
  return { code, status: STATUS[code] ?? 502, body: { error: code, message } };
}

function limitedResponse(c: Ctx, r: LimitResult, hint: string) {
  return c.json({ error: "RATE_LIMITED", message: `Free tier limit reached for today (retry in ${r.retryAfter}s). ${hint}` }, 429, { "retry-after": String(r.retryAfter), "x-ratelimit-remaining": "0" });
}

async function jsonBody(c: Ctx): Promise<Record<string, unknown>> {
  try {
    const b = await c.req.json();
    if (!b || typeof b !== "object" || Array.isArray(b)) throw new Error();
    return b as Record<string, unknown>;
  } catch {
    throw new KyaError("INVALID_INPUT", "body must be a JSON object");
  }
}

/**
 * Runs a use case, logs the call (price, latency, error) and maps KyaError to HTTP.
 * Paid routes: the x402 middleware has already verified the payment; settlement happens after
 * a 2xx only, so an error here is never charged.
 */
async function run(c: Ctx, tool: ToolName, cnpjRoot: string | null, paid: { network: string; payer: string } | null, fn: () => Promise<unknown>) {
  const t0 = Date.now();
  try {
    const value = await fn();
    const id = await logCall(c.env, { transport: paid?.network === "internal" ? "internal" : "http", tool, cnpj_root: cnpjRoot, price_usd: TOOLS[tool].priceUsd, paid: !!paid, network: paid?.network ?? null, payer: paid?.payer ?? null, latency_ms: Date.now() - t0 });
    c.set("callLogId", id);
    return c.json(value as object);
  } catch (err) {
    const { code, status, body } = errorResponse(err);
    c.executionCtx.waitUntil(logCall(c.env, { transport: "http", tool, cnpj_root: cnpjRoot, price_usd: 0, paid: false, latency_ms: Date.now() - t0, error_code: code }));
    return c.json(body, status as 400);
  }
}

const EXAMPLE_REGISTER = { credential_id: "6d0b…", agent: { kind: "evm", id: "0xAbC…" }, principal: { cnpj: "00000000000191" }, challenge: { id: "…", text: "KYA Brasil: prove this agent key acts for a company\n…", expires_at: "…" }, next: { en: "Sign challenge.text with the agent key and with the e-CNPJ, then POST /v1/agents/{id}/prove" } };
const EXAMPLE_VERIFIED = { credential_id: "6d0b…", status: "active", agent: { kind: "evm", id: "0xAbC…" }, principal: { cnpj: "00000000000191", legal_name: "ACME LTDA" }, credential: { mandate: { actions: ["pay"], max_per_operation: 100 }, expires_at: "…", attestation: { key_id: "…", signature: "…" } }, verification: { checked_at: "…" }, attestation: { key_id: "…", signature: "…" } };
const EXAMPLE_ALLOWED = { credential_id: "6d0b…", status: "active", allowed: true, reason: "inside the mandate", checks: [{ field: "actions", ok: true }], not_evaluated: [], attestation: { key_id: "…", signature: "…" } };

const ID_PARAM = { pathParams: { id: "6d0b1c2e-…" }, pathParamsSchema: { properties: { id: { type: "string", description: "credential_id returned by POST /v1/agents" } }, required: ["id"] } };

export function buildHttpApp(env: AppEnv) {
  const app = new Hono<{ Bindings: AppEnv; Variables: Vars }>();

  const facilitator = new HTTPFacilitatorClient(facilitatorConfig(env));
  const resourceServer = new x402ResourceServer(facilitator).registerExtension(bazaarResourceServerExtension);
  registerExactEvmScheme(resourceServer);

  // The facilitator handshake must run inside a request context on Workers (see KYB Brasil): lazy, on the first /v1 request.
  const SYNC_FACILITATOR_ON_START = false;
  let facilitatorReady = false;
  app.use("/v1/*", async (_c, next) => {
    if (!facilitatorReady) {
      await resourceServer.initialize();
      facilitatorReady = true;
    }
    await next();
  });

  // After settlement, attach the receipt (tx hash, payer) to the call log row.
  app.use("/v1/*", async (c, next) => {
    await next();
    const id = c.get("callLogId");
    const settlement = decodeSettlementHeader(c.res.headers.get("PAYMENT-RESPONSE"));
    if (id && settlement?.success) c.executionCtx.waitUntil(attachSettlement(c.env, id, settlement));
  });

  const accepts = (priceUsd: number) => [{ scheme: "exact" as const, price: `$${priceUsd.toFixed(2)}`, network: env.X402_NETWORK, payTo: env.PAY_TO }];
  const resource = { serviceName: SERVICE_NAME, tags: SERVICE_TAGS, mimeType: "application/json" };

  app.use(
    paymentMiddleware(
      {
        "POST /v1/agents": {
          accepts: accepts(TOOLS.kya_register.priceUsd), description: TOOLS.kya_register.description, ...resource,
          extensions: declareDiscoveryExtension({
            bodyType: "json",
            input: { agent: { kind: "evm", id: "0x0000000000000000000000000000000000000001" }, cnpj: "00000000000191", mandate: { actions: ["pay"], max_per_operation: 100, currencies: ["USDC"] } },
            inputSchema: { properties: { agent: { type: "object", description: "{kind: 'evm' | 'web-bot-auth', id: address or base64url Ed25519 public key}" }, cnpj: { type: "string" }, mandate: { type: "object", description: "JSON validated by /.well-known/kya-mandate.schema.json" } }, required: ["agent", "cnpj", "mandate"] },
            output: { example: EXAMPLE_REGISTER, schema: { type: "object" } }
          })
        },
        "POST /v1/agents/:id/renew": {
          accepts: accepts(TOOLS.kya_renew.priceUsd), description: TOOLS.kya_renew.description, ...resource,
          extensions: declareDiscoveryExtension({ bodyType: "json", input: {}, inputSchema: { properties: {}, required: [] }, ...ID_PARAM, output: { example: { credential_id: "6d0b…", challenge: { id: "…", text: "…" } }, schema: { type: "object" } } })
        },
        "GET /v1/agents/:id/verified": {
          accepts: accepts(TOOLS.kya_verify_paid.priceUsd), description: TOOLS.kya_verify_paid.description, ...resource,
          extensions: declareDiscoveryExtension({ input: {}, inputSchema: { properties: {}, required: [] }, ...ID_PARAM, output: { example: EXAMPLE_VERIFIED, schema: { type: "object" } } })
        },
        "GET /v1/agents/:id/allowed": {
          accepts: accepts(TOOLS.kya_check_action.priceUsd), description: TOOLS.kya_check_action.description, ...resource,
          extensions: declareDiscoveryExtension({
            input: { action: "pay", amount: "80", currency: "USDC", counterparty: "33000167000101" },
            inputSchema: { properties: { action: { type: "string" }, amount: { type: "string" }, currency: { type: "string" }, counterparty: { type: "string", description: "CNPJ, domain or wallet address" }, spent_today: { type: "string" } }, required: [] },
            ...ID_PARAM,
            output: { example: EXAMPLE_ALLOWED, schema: { type: "object" } }
          })
        }
      },
      resourceServer,
      undefined,
      undefined,
      SYNC_FACILITATOR_ON_START
    )
  );

  // ---- handlers shared by the paid (x402) and the internal (fiat, shared key) channels ----
  const handlers = {
    register: (c: Ctx, paid: { network: string; payer: string }) =>
      run(c, "kya_register", null, paid, async () => {
        const rl = await checkRegistrations(c.env, ipOf(c));
        if (!rl.allowed) throw new KyaError("RATE_LIMITED", `too many registrations from this IP today; retry in ${rl.retryAfter}s`);
        return service.register(c.env, originOf(c), await jsonBody(c));
      }),
    renew: (c: Ctx, paid: { network: string; payer: string }) => run(c, "kya_renew", null, paid, () => service.renewChallenge(c.env, originOf(c), idOf(c))),
    verified: (c: Ctx, paid: { network: string; payer: string }) =>
      run(c, "kya_verify_paid", null, paid, async () => {
        const v = await service.verify(c.env, idOf(c));
        const out: Record<string, unknown> = { ...v, verification: { checked_at: new Date().toISOString(), checks: ["credential signature", "status", "expiry", "events"], paid: true } };
        const attestation = await signAnswer(c.env, out, originOf(c));
        return attestation ? { ...out, attestation } : out;
      }),
    allowed: (c: Ctx, paid: { network: string; payer: string }) =>
      run(c, "kya_check_action", null, paid, () => service.allowed(c.env, originOf(c), idOf(c), { action: c.req.query("action"), amount: c.req.query("amount"), currency: c.req.query("currency"), counterparty: c.req.query("counterparty"), spent_today: c.req.query("spent_today") }))
  };

  // Paid channel (x402 verified the payment before these run).
  const x402 = { network: env.X402_NETWORK, payer: "x402" };
  app.post("/v1/agents", (c) => handlers.register(c, x402));
  app.post("/v1/agents/:id/renew", (c) => handlers.renew(c, x402));
  app.get("/v1/agents/:id/verified", (c) => handlers.verified(c, x402));
  app.get("/v1/agents/:id/allowed", (c) => handlers.allowed(c, x402));

  // Fiat channel: billed by invoice through a shared key, never through x402.
  const internal = new Hono<{ Bindings: AppEnv; Variables: Vars }>();
  internal.use("*", async (c, next) => {
    const key = c.env.INTERNAL_API_KEY;
    const given = c.req.header("x-internal-key") ?? "";
    if (!key || !timingSafeEqual(given, key)) return c.json({ error: "UNAUTHORIZED", message: "invalid internal key" }, 401);
    await next();
  });
  const fiat = { network: "internal", payer: "internal" };
  internal.post("/agents", (c) => handlers.register(c, fiat));
  internal.post("/agents/:id/renew", (c) => handlers.renew(c, fiat));
  internal.get("/agents/:id/verified", (c) => handlers.verified(c, fiat));
  internal.get("/agents/:id/allowed", (c) => handlers.allowed(c, fiat));
  app.route("/internal/v1", internal);

  // ---- free routes ----
  app.post("/v1/agents/:id/prove", (c) => run(c, "kya_prove", null, null, async () => service.prove(c.env, originOf(c), idOf(c), await jsonBody(c))));
  app.post("/v1/agents/:id/renew/prove", (c) => run(c, "kya_renew", null, null, async () => service.renewProve(c.env, originOf(c), idOf(c), await jsonBody(c))));
  app.post("/v1/agents/:id/revoke", (c) => run(c, "kya_revoke", null, null, async () => service.revoke(c.env, idOf(c), await jsonBody(c))));

  // /by-key before /:id so Hono does not treat "by-key" as an id.
  app.get("/v1/agents/by-key", async (c) => {
    const rl = await checkFreeTier(c.env, `http:${ipOf(c)}`);
    if (!rl.allowed) return limitedResponse(c, rl, "Paid verification (GET /v1/agents/{id}/verified, $0.01) has no limit.");
    c.header("x-ratelimit-remaining", String(rl.remaining));
    return run(c, "kya_verify", null, null, () => service.verifyByKey(c.env, c.req.query("kind"), c.req.query("id")));
  });
  app.get("/v1/agents/:id", async (c) => {
    const rl = await checkFreeTier(c.env, `http:${ipOf(c)}`);
    if (!rl.allowed) return limitedResponse(c, rl, "Paid verification (GET /v1/agents/{id}/verified, $0.01) has no limit.");
    c.header("x-ratelimit-remaining", String(rl.remaining));
    return run(c, "kya_verify", null, null, () => service.verify(c.env, idOf(c)));
  });

  // Revocation list (free, cacheable): everything revoked since ?since= (default 30 days).
  app.get("/v1/revocations", async (c) => {
    const since = c.req.query("since") ?? new Date(Date.now() - 30 * 86400_000).toISOString();
    if (Number.isNaN(Date.parse(since))) return c.json({ error: "INVALID_INPUT", message: "since must be an ISO date" }, 400);
    const revocations = await new Store(c.env.DB).revocations(new Date(since).toISOString());
    return c.json({ since, count: revocations.length, revocations }, 200, { "cache-control": "public, max-age=60" });
  });

  // Attestation: public keys and a verifier for any signed answer or credential (free, pure CPU).
  app.get("/.well-known/kya.json", async (c) => {
    const origin = originOf(c);
    return c.json({
      issuer: origin, service: SERVICE_NAME, version: VERSION, algorithm: "ed25519", keys: await publishedKeys(c.env),
      credential_schema: `${origin}/openapi.json`, mandate_schema: `${origin}/.well-known/kya-mandate.schema.json`,
      verify: `POST ${origin}/v1/verify with the credential (or any signed answer) as body`,
      revocations: `${origin}/v1/revocations`, policy: "The active key signs every credential and verdict. A rotation keeps the old key here as 'retired', so earlier credentials still verify."
    }, 200, { "cache-control": "public, max-age=3600" });
  });
  app.post("/v1/verify", async (c) => {
    let body: Record<string, unknown>;
    try { body = await jsonBody(c); } catch (err) { const { status, body: b } = errorResponse(err); return c.json(b, status as 400); }
    const answer = (body.credential && typeof body.credential === "object" ? body.credential : body) as Record<string, unknown>;
    if (!answer.attestation) return c.json({ error: "INVALID_INPUT", message: "body must be a credential or a signed answer with an attestation field" }, 400);
    const result = await verifyAnswer(c.env, answer);
    const credentialId = typeof answer.credential_id === "string" ? answer.credential_id : null;
    const live = credentialId ? await new Store(c.env.DB).get(credentialId).catch(() => null) : null;
    return c.json({ ...result, credential_id: credentialId, live_status: live ? live.status : null, note: live ? "live_status is the current state; the signature covers the credential as issued" : undefined });
  });
  app.get("/.well-known/kya-mandate.schema.json", (c) => c.json(mandateSchema(originOf(c)), 200, { "cache-control": "public, max-age=3600" }));

  app.get("/terms", (c) => c.text(termsText()));
  app.get("/llms.txt", (c) => c.text(llmsTxt(originOf(c), c.env.X402_NETWORK)));
  app.get("/openapi.json", (c) => c.json(openapiJson(originOf(c), c.env.X402_NETWORK, c.env.PAY_TO)));
  app.get("/health", (c) => c.json({ ok: true }));
  app.get("/status", async (c) => {
    const counts = await new Store(c.env.DB).counts().catch(() => ({}));
    const keys = await publishedKeys(c.env);
    return c.json({ service: SERVICE_NAME, version: VERSION, network: c.env.X402_NETWORK, kyb_channel: c.env.KYB ? "service-binding" : c.env.KYB_URL ? "http-dev" : "missing", attestation_key: keys[0]?.key_id ?? null, credentials: counts, checked_at: new Date().toISOString() });
  });
  app.get("/", (c) => {
    const origin = originOf(c);
    return c.json({ service: SERVICE_NAME, version: VERSION, description: SERVICE_DESCRIPTION, llms: `${origin}/llms.txt`, openapi: `${origin}/openapi.json`, keys: `${origin}/.well-known/kya.json`, mandate_schema: `${origin}/.well-known/kya-mandate.schema.json`, tools: Object.fromEntries(Object.entries(TOOLS).map(([k, t]) => [k, { method: t.method, path: t.path, price_usd: t.priceUsd }])) });
  });

  app.notFound((c) => c.json({ error: "NOT_FOUND", message: `no route ${c.req.method} ${new URL(c.req.url).pathname}; see /llms.txt` }, 404));
  app.onError((err, c) => {
    const { status, body } = errorResponse(err);
    return c.json(body, status as 400);
  });
  return app;
}
