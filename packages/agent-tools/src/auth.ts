/**
 * "Sign in with KYA": authenticate an incoming request from an agent in one step.
 *
 * The agent signs each request with its key and sends four headers; your server verifies the signature,
 * fetches (and caches) the credential, checks that it is active, and hands you who the agent is, which
 * company answers for it, and its mandate. Works with any Web-standard Request (Workers, Hono, Next,
 * Bun, Deno) and with Express through a small adapter.
 *
 *   Server:
 *     const auth = createKyaAuth();
 *     app.use("/api/*", auth.hono());                        // c.get("kya") → { agent, principal, mandate, ... }
 *     app.use(auth.express());                                // req.kya
 *     const r = await auth.authenticate(request);             // anywhere: { ok, ... }
 *
 *   Agent:
 *     const headers = await signRequest({ credentialId, key: { kind: "evm", privateKey }, method: "POST", url, body });
 *     await fetch(url, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });
 *
 * Request text (what the agent signs; the profile is in docs/SPEC.md section 15):
 *   KYA Brasil: request
 *   credential: <credential_id>
 *   method: <METHOD>
 *   url: <origin + path + query, lowercase host>
 *   created: <unix seconds>
 *   expires: <unix seconds>
 *   content-sha256: <hex of the body | ->
 */
import { verifyMessage } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { type ActInput, type ActReceipt, type ActionQuery, type AgentKey, type AgentRequestProof, type CredentialStatus, type KyaClient, type Mandate, type Verdict, type Verification, createKyaClient, type KyaOptions } from "./index";
import { fromBase64Url, toBase64Url } from "./base64url";

export const KYA_HEADERS = { credential: "kya-credential", created: "kya-created", expires: "kya-expires", signature: "kya-signature", content: "kya-content-sha256" } as const;

const enc = new TextEncoder();
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const b64u = toBase64Url;
const unb64u = fromBase64Url;

export async function sha256Hex(data: string | ArrayBuffer | Uint8Array): Promise<string> {
  const bytes = typeof data === "string" ? enc.encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
  return hex(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

/** Canonical URL for the signature: origin (lowercase host) + path + query, no fragment. */
export function canonicalUrl(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.host.toLowerCase()}${u.pathname}${u.search}`;
}

export function requestText(p: { credentialId: string; method: string; url: string; created: number; expires: number; contentSha256?: string | null }): string {
  return [
    "KYA Brasil: request",
    `credential: ${p.credentialId}`,
    `method: ${p.method.toUpperCase()}`,
    `url: ${canonicalUrl(p.url)}`,
    `created: ${p.created}`,
    `expires: ${p.expires}`,
    `content-sha256: ${p.contentSha256 ?? "-"}`
  ].join("\n");
}

// --- Agent side -------------------------------------------------------------------------------

export type SigningKey = { kind: "evm" | "erc8004"; privateKey: `0x${string}` } | { kind: "web-bot-auth"; privateKey: CryptoKey | string };

/** Signs a request with the agent key and returns the KYA headers to send with it. */
export async function signRequest(p: { credentialId: string; key: SigningKey; method: string; url: string; body?: string | ArrayBuffer | Uint8Array | null; ttlSeconds?: number; now?: Date }): Promise<Record<string, string>> {
  const created = Math.floor((p.now ?? new Date()).getTime() / 1000);
  const expires = created + (p.ttlSeconds ?? 60);
  const contentSha256 = p.body !== undefined && p.body !== null && (typeof p.body !== "string" || p.body.length > 0) ? await sha256Hex(p.body) : null;
  const text = requestText({ credentialId: p.credentialId, method: p.method, url: p.url, created, expires, contentSha256 });
  let signature: string;
  if (p.key.kind === "web-bot-auth") {
    const key = typeof p.key.privateKey === "string" ? await crypto.subtle.importKey("pkcs8", unb64u(p.key.privateKey.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")), { name: "Ed25519" }, false, ["sign"]) : p.key.privateKey;
    signature = b64u(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, enc.encode(text))));
  } else {
    signature = await privateKeyToAccount(p.key.privateKey).signMessage({ message: text });
  }
  const headers: Record<string, string> = { [KYA_HEADERS.credential]: p.credentialId, [KYA_HEADERS.created]: String(created), [KYA_HEADERS.expires]: String(expires), [KYA_HEADERS.signature]: signature };
  if (contentSha256) headers[KYA_HEADERS.content] = contentSha256;
  return headers;
}

// --- Server side ------------------------------------------------------------------------------

export interface KyaAuthOptions extends KyaOptions {
  /** How long a fetched credential is reused before asking the issuer again (ms). Default 60 000. */
  cacheTtlMs?: number;
  /** Max clock difference accepted for `created` (seconds). Default 300. */
  maxSkewSeconds?: number;
  /** Max signature lifetime accepted (seconds), whatever `expires` says. Default 600. */
  maxTtlSeconds?: number;
  /** Verify the body hash when the request has a body. Default true. */
  requireBodyHash?: boolean;
}

export interface KyaContext {
  credential_id: string;
  agent: AgentKey;
  principal: Verification["principal"];
  status: CredentialStatus;
  mandate: Mandate;
  credential: Verification["credential"];
  /** Which key verified the request signature. */
  signer: string;
  /** Whether the body hash was checked ("verified"), absent from the signature ("none") or not checkable ("skipped"). */
  body: "verified" | "none" | "skipped";
  /** Local evaluation of the mandate (no daily ceilings; those need the issuer). */
  check(q: ActionQuery): LocalVerdict;
  /** Signed verdict from the issuer ($0.01, needs privateKey or internalKey in the options). */
  allowed(q: ActionQuery): Promise<Verdict>;
  /** The agent's signed request, kept as the proof of origin of an act (absent for signed responses). */
  request?: AgentRequestProof;
  /**
   * Registers the act this request led to ($0.02) with the request as its proof of origin (D-18), so it counts
   * toward the agent's daily ceiling across counterparties.
   */
  registerAct(act: Omit<ActInput, "agent_request">): Promise<ActReceipt>;
}

export type KyaAuthResult = { ok: true; kya: KyaContext } | { ok: false; status: 401 | 403 | 502; error: string; message: string };

export interface LocalVerdict { allowed: boolean; checks: { rule: string; ok: boolean; detail: string }[]; not_evaluated: string[] }

const RESERVED = ["actions", "max_per_operation", "max_per_day", "currencies", "counterparties", "valid_from", "valid_until"];

function normalizeCounterparty(c: string): string {
  const t = c.trim();
  const digits = t.replace(/\D/g, "");
  if (digits.length === 14 && /^[\d./-]+$/.test(t)) return digits;
  if (/^0x[0-9a-fA-F]{40}$/.test(t)) return t.toLowerCase();
  // Domain or URL: drop the scheme, then everything from the first "/" (indexOf, no backtracking regex).
  const host = t.toLowerCase().replace(/^https?:\/\//, "");
  const slash = host.indexOf("/");
  return slash === -1 ? host : host.slice(0, slash);
}

/**
 * Local evaluation of the reserved mandate fields: actions, max_per_operation, currencies, counterparties
 * (with `*.` wildcards), valid_from / valid_until. `max_per_day` is listed as not evaluated: only the issuer
 * knows what was registered today (use ctx.allowed or registerAct).
 */
export function checkMandate(mandate: Mandate, q: ActionQuery, now = new Date()): LocalVerdict {
  const checks: LocalVerdict["checks"] = [];
  const push = (rule: string, ok: boolean, detail: string) => checks.push({ rule, ok, detail });
  if (mandate.valid_from) push("valid_from", now >= new Date(mandate.valid_from), `mandate starts ${mandate.valid_from}`);
  if (mandate.valid_until) push("valid_until", now <= new Date(mandate.valid_until), `mandate ends ${mandate.valid_until}`);
  if (mandate.actions && q.action) push("actions", mandate.actions.includes(q.action), `action "${q.action}" ${mandate.actions.includes(q.action) ? "is" : "is not"} in [${mandate.actions.join(", ")}]`);
  if (mandate.currencies && q.currency) {
    const c = q.currency.toUpperCase();
    push("currencies", mandate.currencies.includes(c), `currency ${c} ${mandate.currencies.includes(c) ? "allowed" : "not in"} [${mandate.currencies.join(", ")}]`);
  }
  if (mandate.max_per_operation && q.amount !== undefined) {
    const same = !q.currency || q.currency.toUpperCase() === mandate.max_per_operation.currency;
    push("max_per_operation", same && q.amount <= mandate.max_per_operation.amount, same ? `${q.amount} vs ceiling ${mandate.max_per_operation.amount} ${mandate.max_per_operation.currency}` : `ceiling is in ${mandate.max_per_operation.currency}, operation in ${q.currency}`);
  }
  if (mandate.counterparties && mandate.counterparties.length && q.counterparty) {
    const c = normalizeCounterparty(q.counterparty);
    const ok = mandate.counterparties.some((m) => {
      const n = normalizeCounterparty(m);
      return n === c || (n.startsWith("*.") && (c === n.slice(2) || c.endsWith(n.slice(1))));
    });
    push("counterparties", ok, `${c} ${ok ? "is" : "is not"} an allowed counterparty`);
  }
  const not_evaluated = Object.keys(mandate).filter((k) => !RESERVED.includes(k));
  if (mandate.max_per_day) not_evaluated.push("max_per_day (only the issuer knows today's registered total)");
  return { allowed: checks.every((c) => c.ok), checks, not_evaluated };
}

export interface KyaAuth {
  client: KyaClient;
  /** Authenticate any Web-standard Request. Never throws; read `ok`. */
  authenticate(request: Request, opts?: { body?: string | ArrayBuffer | Uint8Array | null }): Promise<KyaAuthResult>;
  /** Same, from the parts (for frameworks that already parsed the request). */
  authenticateParts(p: { method: string; url: string; headers: Headers | Record<string, string | string[] | undefined>; body?: string | ArrayBuffer | Uint8Array | null }): Promise<KyaAuthResult>;
  /** Low level: verify a signature by a credential's agent key over a text you built (signed responses use it). */
  verifySigned(p: { credentialId: string; text: string; signature: string; body?: KyaContext["body"] }): Promise<KyaAuthResult>;
  /** Hono middleware: sets c.set("kya", ctx) or answers 401/403 JSON. */
  hono(): (c: HonoLikeContext, next: () => Promise<void>) => Promise<Response | void>;
  /** Express middleware: sets req.kya or answers 401/403 JSON. Verifies the body when req.body is a string or Buffer. */
  express(): (req: ExpressLikeRequest, res: ExpressLikeResponse, next: (err?: unknown) => void) => void;
  /** Wrap a fetch handler (Workers, Deno, Bun): handler(request, kya). */
  fetchHandler(handler: (request: Request, kya: KyaContext) => Promise<Response> | Response): (request: Request) => Promise<Response>;
  /** Forget cached credentials (tests, or after a revocation you learned about). */
  clearCache(): void;
}

export interface HonoLikeContext { req: { raw: Request }; set: (k: string, v: unknown) => void; json: (body: unknown, status?: number) => Response }
export interface ExpressLikeRequest { method: string; protocol?: string; originalUrl?: string; url?: string; headers: Record<string, string | string[] | undefined>; body?: unknown; get?: (name: string) => string | undefined; kya?: KyaContext }
export interface ExpressLikeResponse { status: (code: number) => ExpressLikeResponse; json: (body: unknown) => unknown }

const headerOf = (headers: Headers | Record<string, string | string[] | undefined>, name: string): string | null => {
  if (headers instanceof Headers) return headers.get(name);
  const v = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] ?? null : v ?? null;
};

export function createKyaAuth(opts: KyaAuthOptions = {}): KyaAuth {
  const client = createKyaClient(opts);
  const cacheTtl = opts.cacheTtlMs ?? 60_000;
  const maxSkew = opts.maxSkewSeconds ?? 300;
  const maxTtl = opts.maxTtlSeconds ?? 600;
  const requireBodyHash = opts.requireBodyHash ?? true;
  const cache = new Map<string, { at: number; v: Verification }>();

  async function verification(id: string): Promise<Verification> {
    const hit = cache.get(id);
    if (hit && Date.now() - hit.at < cacheTtl) return hit.v;
    const v = await client.verify(id);
    cache.set(id, { at: Date.now(), v });
    return v;
  }

  async function verifySignature(agent: AgentKey, text: string, signature: string): Promise<{ ok: boolean; signer: string }> {
    try {
      if (agent.kind === "web-bot-auth") {
        const key = await crypto.subtle.importKey("raw", unb64u(agent.id), { name: "Ed25519" }, false, ["verify"]);
        const sig = unb64u(signature);
        return { ok: sig.length === 64 && (await crypto.subtle.verify({ name: "Ed25519" }, key, sig, enc.encode(text))), signer: agent.id };
      }
      const address = agent.kind === "evm" ? agent.id : agent.wallet;
      if (!address || !/^0x[0-9a-fA-F]{130}$/.test(signature)) return { ok: false, signer: address ?? "" };
      return { ok: await verifyMessage({ address: address as `0x${string}`, message: text, signature: signature as `0x${string}` }), signer: address };
    } catch {
      return { ok: false, signer: "" };
    }
  }

  const fail = (status: 401 | 403 | 502, error: string, message: string): KyaAuthResult => ({ ok: false, status, error, message });

  async function authenticateParts(p: { method: string; url: string; headers: Headers | Record<string, string | string[] | undefined>; body?: string | ArrayBuffer | Uint8Array | null }): Promise<KyaAuthResult> {
    const credentialId = headerOf(p.headers, KYA_HEADERS.credential);
    const created = Number(headerOf(p.headers, KYA_HEADERS.created));
    const expires = Number(headerOf(p.headers, KYA_HEADERS.expires));
    const signature = headerOf(p.headers, KYA_HEADERS.signature);
    const contentHeader = headerOf(p.headers, KYA_HEADERS.content);
    if (!credentialId || !signature || !Number.isFinite(created) || !Number.isFinite(expires)) return fail(401, "KYA_HEADERS_MISSING", `send ${KYA_HEADERS.credential}, ${KYA_HEADERS.created}, ${KYA_HEADERS.expires} and ${KYA_HEADERS.signature}`);
    const now = Math.floor(Date.now() / 1000);
    if (created > now + maxSkew) return fail(401, "KYA_SIGNATURE_NOT_YET_VALID", "created is in the future");
    if (expires < now) return fail(401, "KYA_SIGNATURE_EXPIRED", "expires is in the past");
    if (expires - created > maxTtl || expires < created) return fail(401, "KYA_SIGNATURE_TTL", `signature lifetime must be between 0 and ${maxTtl}s`);

    let bodyState: KyaContext["body"] = "none";
    if (p.body !== undefined && p.body !== null && (typeof p.body !== "string" || p.body.length > 0)) {
      if (!contentHeader) {
        if (requireBodyHash) return fail(401, "KYA_BODY_UNSIGNED", `the request has a body but no ${KYA_HEADERS.content} header`);
        bodyState = "skipped";
      } else if ((await sha256Hex(p.body)) !== contentHeader.toLowerCase()) return fail(401, "KYA_BODY_MISMATCH", "body hash does not match the signed hash");
      else bodyState = "verified";
    } else if (contentHeader) bodyState = "skipped";

    let v: Verification;
    try {
      v = await verification(credentialId);
    } catch (e) {
      const status = (e as { status?: number }).status;
      return status === 404 ? fail(401, "KYA_CREDENTIAL_UNKNOWN", "unknown credential_id") : fail(502, "KYA_ISSUER_UNAVAILABLE", (e as Error).message);
    }
    const text = requestText({ credentialId, method: p.method, url: p.url, created, expires, contentSha256: contentHeader });
    const request: AgentRequestProof = { method: p.method.toUpperCase(), url: p.url, created, expires, signature, ...(contentHeader ? { content_sha256: contentHeader.toLowerCase() } : {}) };
    return finish(credentialId, v, text, signature, bodyState, request);
  }

  async function finish(credentialId: string, v: Verification, text: string, signature: string, bodyState: KyaContext["body"], request?: AgentRequestProof): Promise<KyaAuthResult> {
    const sig = await verifySignature(v.agent, text, signature);
    if (!sig.ok) return fail(401, "KYA_BAD_SIGNATURE", "signature does not match the credential's agent key over the signed text");
    if (v.status !== "active") return fail(403, "KYA_CREDENTIAL_NOT_ACTIVE", `credential is ${v.status}${v.status_reason ? `: ${v.status_reason}` : ""}`);
    const mandate = v.credential?.mandate ?? {};
    const ctx: KyaContext = {
      credential_id: credentialId,
      agent: v.agent,
      principal: v.principal,
      status: v.status,
      mandate,
      credential: v.credential,
      signer: sig.signer,
      body: bodyState,
      check: (q) => checkMandate(mandate, q),
      allowed: (q) => client.allowed(credentialId, q),
      ...(request ? { request } : {}),
      registerAct: (act) => client.registerAct(credentialId, request ? { ...act, agent_request: request } : act)
    };
    return { ok: true, kya: ctx };
  }

  /** Low level: verify a signature by a credential's agent key over a text you built yourself (used for signed responses). */
  async function verifySigned(p: { credentialId: string; text: string; signature: string; body?: KyaContext["body"] }): Promise<KyaAuthResult> {
    let v: Verification;
    try {
      v = await verification(p.credentialId);
    } catch (e) {
      const status = (e as { status?: number }).status;
      return status === 404 ? fail(401, "KYA_CREDENTIAL_UNKNOWN", "unknown credential_id") : fail(502, "KYA_ISSUER_UNAVAILABLE", (e as Error).message);
    }
    return finish(p.credentialId, v, p.text, p.signature, p.body ?? "none");
  }

  const auth: KyaAuth = {
    client,
    authenticateParts,
    verifySigned,
    async authenticate(request, o = {}) {
      let body = o.body;
      if (body === undefined && request.body && !["GET", "HEAD"].includes(request.method)) body = await request.clone().arrayBuffer();
      return authenticateParts({ method: request.method, url: request.url, headers: request.headers, body });
    },
    hono() {
      return async (c, next) => {
        const r = await auth.authenticate(c.req.raw);
        if (!r.ok) return c.json({ error: r.error, message: r.message }, r.status);
        c.set("kya", r.kya);
        await next();
      };
    },
    express() {
      return (req, res, next) => {
        const host = req.get?.("host") ?? (headerOf(req.headers, "host") || "localhost");
        const proto = headerOf(req.headers, "x-forwarded-proto") || req.protocol || "http";
        const url = `${proto}://${host}${req.originalUrl ?? req.url ?? "/"}`;
        const raw = typeof req.body === "string" || req.body instanceof Uint8Array ? req.body : req.body && typeof req.body === "object" ? JSON.stringify(req.body) : undefined;
        authenticateParts({ method: req.method, url, headers: req.headers, body: raw })
          .then((r) => {
            if (!r.ok) return res.status(r.status).json({ error: r.error, message: r.message });
            req.kya = r.kya;
            next();
          })
          .catch(next);
      };
    },
    fetchHandler(handler) {
      return async (request) => {
        const r = await auth.authenticate(request);
        if (!r.ok) return new Response(JSON.stringify({ error: r.error, message: r.message }), { status: r.status, headers: { "content-type": "application/json" } });
        return handler(request, r.kya);
      };
    },
    clearCache: () => cache.clear()
  };
  return auth;
}

// --- Mutual authentication (agent to agent) --------------------------------------------------
//
// When both sides are agents, the caller proves itself with the request headers above and the callee
// proves itself by signing the response, bound to the request it answers:
//
//   KYA Brasil: response
//   credential: <callee credential_id>
//   in-reply-to: <sha256 hex of the request's KYA-Signature>
//   created: <unix seconds>
//   expires: <unix seconds>
//   content-sha256: <hex of the response body | ->
//
// Response headers: the same KYA-* names plus KYA-In-Reply-To. The caller verifies with the callee's
// credential (agent key, active status) exactly as a server verifies a request.

export const KYA_REPLY_HEADER = "kya-in-reply-to";

export function responseText(p: { credentialId: string; inReplyTo: string; created: number; expires: number; contentSha256?: string | null }): string {
  return ["KYA Brasil: response", `credential: ${p.credentialId}`, `in-reply-to: ${p.inReplyTo}`, `created: ${p.created}`, `expires: ${p.expires}`, `content-sha256: ${p.contentSha256 ?? "-"}`].join("\n");
}

async function signText(key: SigningKey, text: string): Promise<string> {
  if (key.kind === "web-bot-auth") {
    const k = typeof key.privateKey === "string" ? await crypto.subtle.importKey("pkcs8", unb64u(key.privateKey.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")), { name: "Ed25519" }, false, ["sign"]) : key.privateKey;
    return b64u(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, k, enc.encode(text))));
  }
  return privateKeyToAccount(key.privateKey).signMessage({ message: text });
}

/** Callee side: headers that prove who answered, bound to the request signature it replies to. */
export async function signResponse(p: { credentialId: string; key: SigningKey; requestSignature: string; body?: string | ArrayBuffer | Uint8Array | null; ttlSeconds?: number; now?: Date }): Promise<Record<string, string>> {
  const created = Math.floor((p.now ?? new Date()).getTime() / 1000);
  const expires = created + (p.ttlSeconds ?? 60);
  const inReplyTo = await sha256Hex(p.requestSignature);
  const contentSha256 = p.body !== undefined && p.body !== null && (typeof p.body !== "string" || p.body.length > 0) ? await sha256Hex(p.body) : null;
  const signature = await signText(p.key, responseText({ credentialId: p.credentialId, inReplyTo, created, expires, contentSha256 }));
  const headers: Record<string, string> = { [KYA_HEADERS.credential]: p.credentialId, [KYA_REPLY_HEADER]: inReplyTo, [KYA_HEADERS.created]: String(created), [KYA_HEADERS.expires]: String(expires), [KYA_HEADERS.signature]: signature };
  if (contentSha256) headers[KYA_HEADERS.content] = contentSha256;
  return headers;
}

export type KyaResponseResult = { ok: true; kya: Omit<KyaContext, "check" | "allowed"> & { check: KyaContext["check"]; allowed: KyaContext["allowed"] } } | { ok: false; error: string; message: string };

/**
 * Caller side: verify that a response was signed by an active KYA credential and answers *this* request.
 * `requestSignature` is the KYA-Signature header the caller sent.
 */
export async function verifyResponse(auth: KyaAuth, response: Response, requestSignature: string, opts: { body?: string | ArrayBuffer | Uint8Array | null; maxSkewSeconds?: number } = {}): Promise<KyaResponseResult> {
  const h = response.headers;
  const credentialId = h.get(KYA_HEADERS.credential);
  const inReplyTo = h.get(KYA_REPLY_HEADER);
  const created = Number(h.get(KYA_HEADERS.created));
  const expires = Number(h.get(KYA_HEADERS.expires));
  const signature = h.get(KYA_HEADERS.signature);
  const contentHeader = h.get(KYA_HEADERS.content);
  const fail = (error: string, message: string): KyaResponseResult => ({ ok: false, error, message });
  if (!credentialId || !inReplyTo || !signature || !Number.isFinite(created) || !Number.isFinite(expires)) return fail("KYA_RESPONSE_UNSIGNED", "the response carries no KYA signature");
  if (inReplyTo !== (await sha256Hex(requestSignature))) return fail("KYA_RESPONSE_MISMATCH", "the response answers a different request");
  const now = Math.floor(Date.now() / 1000);
  if (created > now + (opts.maxSkewSeconds ?? 300) || expires < now) return fail("KYA_RESPONSE_EXPIRED", "response signature outside its validity window");
  let body = opts.body;
  if (body === undefined) body = await response.clone().arrayBuffer();
  let bodyState: KyaContext["body"] = "none";
  if (body && (typeof body !== "string" ? (body as ArrayBuffer | Uint8Array).byteLength > 0 : body.length > 0)) {
    if (!contentHeader) return fail("KYA_RESPONSE_BODY_UNSIGNED", "the response has a body but no content hash");
    if ((await sha256Hex(body)) !== contentHeader.toLowerCase()) return fail("KYA_RESPONSE_BODY_MISMATCH", "response body does not match the signed hash");
    bodyState = "verified";
  }
  // Same credential lookup, key selection and status rule as for requests, over the response text.
  const probe = await auth.verifySigned({ credentialId, text: responseText({ credentialId, inReplyTo, created, expires, contentSha256: contentHeader }), signature, body: bodyState });
  if (!probe.ok) return fail(probe.error.replace("KYA_", "KYA_RESPONSE_"), probe.message);
  return { ok: true, kya: probe.kya };
}

/**
 * Caller side, all in one: a fetch that signs the request with your credential and, when the other side
 * answers with KYA headers, verifies them. `callee` is null when the response was not signed.
 */
export function createKyaAgent(p: { credentialId: string; key: SigningKey; auth?: KyaAuth; authOptions?: KyaAuthOptions; fetch?: typeof fetch; ttlSeconds?: number }) {
  const auth = p.auth ?? createKyaAuth(p.authOptions);
  const base = p.fetch ?? fetch;
  return {
    auth,
    headers: (method: string, url: string, body?: string | ArrayBuffer | Uint8Array | null) => signRequest({ credentialId: p.credentialId, key: p.key, method, url, body, ttlSeconds: p.ttlSeconds }),
    async fetch(url: string, init: RequestInit & { body?: string | ArrayBuffer | Uint8Array | null } = {}): Promise<{ response: Response; callee: KyaResponseResult | null }> {
      const method = (init.method ?? "GET").toUpperCase();
      const body = init.body ?? null;
      const signed = await signRequest({ credentialId: p.credentialId, key: p.key, method, url, body, ttlSeconds: p.ttlSeconds });
      const response = await base(url, { ...init, method, headers: { ...(init.headers as Record<string, string>), ...signed }, body: body as BodyInit | null });
      const callee = response.headers.get(KYA_HEADERS.signature) ? await verifyResponse(auth, response, signed[KYA_HEADERS.signature]!) : null;
      return { response, callee };
    }
  };
}
