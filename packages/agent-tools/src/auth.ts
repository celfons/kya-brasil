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
 *   Sub-agent (D-30, the credential's mandate allows delegation):
 *     const chain = await signDelegation({ credential, key: parentKey, delegate: { kind: "evm", id: sub }, mandate: { actions: ["quote"] }, ttlSeconds: 600 });
 *     const headers = await signRequest({ credentialId, key: subKey, delegation: chain, method: "GET", url });
 *
 * Request text (what the agent signs; the profile is in docs/SPEC.md section 14):
 *   KYA Brasil: request
 *   credential: <credential_id>
 *   delegation: <sha256 hex of the KYA-Delegation header>      (only on delegated requests)
 *   method: <METHOD>
 *   url: <origin + path + query, lowercase host>
 *   created: <unix seconds>
 *   expires: <unix seconds>
 *   content-sha256: <hex of the body | ->
 */
import { verifyMessage } from "viem";
import { type Delegation, type DelegationAnchor, type FreshnessVerdict, type PrincipalProof, type StatusEvidence, SELF_ISSUER, checkFreshAction, decodePrincipalProofHeader, encodeDelegationHeader, encodePrincipalProofHeader, decodeDelegationHeader, prepareDelegation, verifyDelegationChain } from "@kya-brasil/core";
import { privateKeyToAccount } from "viem/accounts";
import { type ActionQuery, type AgentKey, type Credential, type CredentialStatus, type KyaClient, type Mandate, type Verdict, type Verification, createKyaClient, type KyaOptions } from "./index.js";
import { fromBase64Url, toBase64Url } from "./base64url.js";
import { type KyaOfflineOptions, type ResolvedOffline, certificateStatusOf, decodeCredentialHeader, encodeCredentialHeader, resolveOffline, verifyPresentedCredential } from "./offline.js";

export { type CertificateStatusQuery, type KyaOfflineOptions, decodeCredentialHeader, encodeCredentialHeader } from "./offline.js";

/**
 * Request headers. `credentialDocument` and `principalProof` are sent only to verifiers that work without the
 * issuer (offline option): the credential's JSON and the principal's proof, both base64url.
 */
export const KYA_HEADERS = { credential: "kya-credential", created: "kya-created", expires: "kya-expires", signature: "kya-signature", content: "kya-content-sha256", delegation: "kya-delegation", credentialDocument: "kya-credential-document", principalProof: "kya-principal-proof" } as const;

export type { Delegation } from "@kya-brasil/core";

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

export function requestText(p: { credentialId: string; method: string; url: string; created: number; expires: number; contentSha256?: string | null; delegationSha256?: string | null }): string {
  return [
    "KYA Brasil: request",
    `credential: ${p.credentialId}`,
    ...(p.delegationSha256 ? [`delegation: ${p.delegationSha256}`] : []),
    `method: ${p.method.toUpperCase()}`,
    `url: ${canonicalUrl(p.url)}`,
    `created: ${p.created}`,
    `expires: ${p.expires}`,
    `content-sha256: ${p.contentSha256 ?? "-"}`
  ].join("\n");
}

// --- Agent side -------------------------------------------------------------------------------

const importPkcs8 = (pem: string, extractable = false) => crypto.subtle.importKey("pkcs8", unb64u(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")), { name: "Ed25519" }, extractable, ["sign"]);

async function signText(key: SigningKey, text: string): Promise<string> {
  if (key.kind === "web-bot-auth") {
    const k = typeof key.privateKey === "string" ? await importPkcs8(key.privateKey) : key.privateKey;
    return b64u(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, k, enc.encode(text))));
  }
  return privateKeyToAccount(key.privateKey).signMessage({ message: text });
}

export type SigningKey = { kind: "evm" | "erc8004"; privateKey: `0x${string}` } | { kind: "web-bot-auth"; privateKey: CryptoKey | string };

/**
 * Signs a request with the agent key and returns the KYA headers to send with it. A sub-agent passes its
 * `delegation` chain (from signDelegation) and signs with its own key. `present` adds the credential and the
 * principal's proof (KYA-Credential-Document, KYA-Principal-Proof) for verifiers that work without the issuer.
 */
export async function signRequest(p: { credentialId: string; key: SigningKey; method: string; url: string; body?: string | ArrayBuffer | Uint8Array | null; ttlSeconds?: number; now?: Date; delegation?: Delegation[]; present?: { credential: Credential | object; proof: PrincipalProof } }): Promise<Record<string, string>> {
  const created = Math.floor((p.now ?? new Date()).getTime() / 1000);
  const expires = created + (p.ttlSeconds ?? 60);
  const contentSha256 = p.body !== undefined && p.body !== null && (typeof p.body !== "string" || p.body.length > 0) ? await sha256Hex(p.body) : null;
  const delegationHeader = p.delegation && p.delegation.length ? encodeDelegationHeader(p.delegation) : null;
  const delegationSha256 = delegationHeader ? await sha256Hex(delegationHeader) : null;
  const text = requestText({ credentialId: p.credentialId, method: p.method, url: p.url, created, expires, contentSha256, delegationSha256 });
  const signature = await signText(p.key, text);
  const headers: Record<string, string> = { [KYA_HEADERS.credential]: p.credentialId, [KYA_HEADERS.created]: String(created), [KYA_HEADERS.expires]: String(expires), [KYA_HEADERS.signature]: signature };
  if (contentSha256) headers[KYA_HEADERS.content] = contentSha256;
  if (delegationHeader) headers[KYA_HEADERS.delegation] = delegationHeader;
  if (p.present) {
    headers[KYA_HEADERS.credentialDocument] = encodeCredentialHeader(p.present.credential as Credential);
    headers[KYA_HEADERS.principalProof] = encodePrincipalProofHeader(p.present.proof);
  }
  return headers;
}

/** The key a signing key verifies as, in the form a credential or a delegation names it. */
export async function agentKeyOf(key: SigningKey): Promise<AgentKey> {
  if (key.kind !== "web-bot-auth") return { kind: "evm", id: privateKeyToAccount(key.privateKey).address };
  const k = typeof key.privateKey === "string" ? await importPkcs8(key.privateKey, true) : key.privateKey;
  const jwk = (await crypto.subtle.exportKey("jwk", k)) as JsonWebKey;
  if (!jwk.x) throw new Error("cannot derive the Ed25519 public key from this private key");
  return { kind: "web-bot-auth", id: jwk.x };
}

/**
 * Delegation to a sub-agent (D-30): hands `delegate` a mandate contained in the delegator's, for `ttlSeconds`
 * (at most the mandate's `delegation.max_ttl_seconds`). `key` is the credential's agent key, or, to delegate
 * again, the key of the last delegate in `chain`. Returns the new chain; the sub-agent sends it with
 * signRequest({ delegation }). Nothing goes to the issuer.
 */
export async function signDelegation(p: { credential: DelegationAnchor | Credential; key: SigningKey; delegate: { kind: "evm" | "web-bot-auth"; id: string }; mandate: Mandate; ttlSeconds: number; chain?: Delegation[]; now?: Date }): Promise<Delegation[]> {
  const chain = p.chain ?? [];
  const { delegation, text } = await prepareDelegation({ credential: p.credential as DelegationAnchor, chain, delegate: p.delegate, mandate: p.mandate, ttlSeconds: p.ttlSeconds, now: p.now });
  const signature = await signText(p.key, text);
  return [...chain, { ...delegation, signature }];
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
  /**
   * Opt-in: accept requests that carry their own credential and principal's proof, with no issuer in the path
   * (SPEC sections 14, 18-20). Trust anchors, clock and certificate status are required (construction throws
   * without them); see KyaOfflineOptions. Absent: behaviour unchanged.
   */
  offline?: KyaOfflineOptions;
  /**
   * Opt-in replay protection (SPEC section 14): every accepted request is recorded under the SHA-256 of its signed
   * request text, until the request's own `KYA-Expires`, and a request already recorded is refused with 401
   * KYA_REQUEST_REPLAYED. Use memoryReplayCache() for one process, or your own store (Redis SET NX with an expiry,
   * a database unique key) when several instances serve the same API. Requires a finite maxTtlSeconds.
   */
  replayCache?: ReplayCache;
}

/**
 * Where the verifier remembers the requests it accepted. `seen` MUST atomically record `key` until `expiresAt`
 * (inclusive) and return whether it was already recorded and not yet expired. `now` is the verifier's clock
 * (offline.now in offline mode), so that eviction follows the same clock as the signature window.
 */
export interface ReplayCache {
  seen(key: string, expiresAt: Date, now: Date): Promise<boolean>;
}

/**
 * In-memory ReplayCache for a single process: entries live until the request's expiry (never shorter, which would
 * let a replay through inside the window) and expired ones are evicted as the clock passes them. `maxEntries`
 * bounds memory: when full of live entries, a new request is refused as if seen (fail closed) rather than
 * forgetting a live one.
 */
export function memoryReplayCache(opts: { maxEntries?: number } = {}): ReplayCache & { size(): number; clear(): void } {
  const max = opts.maxEntries ?? 100_000;
  const entries = new Map<string, number>();
  let lastSweep = -Infinity;
  const evict = (now: number) => {
    for (const [k, exp] of entries) if (exp < now) entries.delete(k);
    lastSweep = now;
  };
  return {
    async seen(key, expiresAt, now) {
      const t = now.getTime();
      const hit = entries.get(key);
      if (hit !== undefined && hit >= t) return true;
      if (Math.abs(t - lastSweep) > 1000 || entries.size >= max) evict(t);
      if (entries.size >= max) return true;
      entries.set(key, expiresAt.getTime());
      return false;
    },
    size: () => entries.size,
    clear: () => entries.clear()
  };
}

export interface KyaContext {
  credential_id: string;
  agent: AgentKey;
  principal: Verification["principal"];
  status: CredentialStatus;
  mandate: Mandate;
  credential: Verification["credential"];
  /** Which key verified the request signature (the sub-agent's key on a delegated request). */
  signer: string;
  /**
   * D-30: present when a sub-agent signed the request under a delegation chain. `agent` above stays the
   * credential's agent; `delegate` is the sub-agent; every mandate in `mandates` must allow an action.
   */
  delegation: { depth: number; delegate: AgentKey; expires_at: string; chain: Delegation[]; mandates: Mandate[] } | null;
  /** Whether the body hash was checked ("verified"), absent from the signature ("none") or not checkable ("skipped"). */
  body: "verified" | "none" | "skipped";
  /**
   * Present when the request was verified without the issuer (`offline` option): the credential came with the
   * request, the principal's proof verified up to your anchors, and `evidence` is what your certificateStatus
   * returned. check() and allowed() are then local, at your clock (allowed() never calls the issuer).
   */
  offline?: { issuer: string; self_issued: boolean; verified_at: string; evidence: StatusEvidence[] };
  /** Local evaluation of the mandate (no daily ceilings; those need the issuer). On a delegated request, of every mandate in the chain. */
  check(q: ActionQuery): LocalVerdict;
  /**
   * Signed verdict from the issuer ($0.01, needs privateKey or internalKey in the options). The issuer evaluates
   * the credential's mandate; on a delegated request the delegated mandates are evaluated here first, and when
   * one refuses the answer is that local refusal (unsigned, `delegation_level` set, the issuer is not called).
   */
  allowed(q: ActionQuery): Promise<Verdict>;
}

export type KyaAuthResult = { ok: true; kya: KyaContext } | { ok: false; status: 401 | 403 | 502; error: string; message: string };

export interface LocalVerdict {
  allowed: boolean;
  checks: { rule: string; ok: boolean; detail: string }[];
  not_evaluated: string[];
  /** Offline mode with a freshness policy: the status freshness verdict (SPEC section 18, checkFreshAction). */
  freshness?: FreshnessVerdict;
}

const RESERVED = ["actions", "max_per_operation", "max_per_day", "currencies", "counterparties", "payment_instruments", "valid_from", "valid_until", "delegation"];

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
 * (with `*.` wildcards), payment_instruments (when you pass payment_ref_sha256), valid_from / valid_until, and
 * max_per_day when you pass spent_today (nobody else counts it: the issuer keeps no record of acts).
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
  if (mandate.max_per_day && q.amount !== undefined && q.spent_today !== undefined) {
    const total = q.amount + q.spent_today;
    const same = !q.currency || q.currency.toUpperCase() === mandate.max_per_day.currency;
    push("max_per_day", same && total <= mandate.max_per_day.amount, same ? `${total} today (incl. this one) vs ceiling ${mandate.max_per_day.amount} ${mandate.max_per_day.currency}` : `ceiling is in ${mandate.max_per_day.currency}, operation in ${q.currency}`);
  }
  const instruments = Array.isArray(mandate.payment_instruments) ? mandate.payment_instruments : [];
  if (instruments.length && q.payment_ref_sha256) {
    const h = q.payment_ref_sha256.trim().toLowerCase();
    const net = q.payment_network?.trim().toLowerCase();
    const hit = instruments.find((p) => p.ref_sha256 === h && (!net || p.network === net));
    push("payment_instruments", !!hit, hit ? `${hit.network} instrument ${h.slice(0, 12)}… is authorized` : `instrument ${net ? `${net} ` : ""}${h.slice(0, 12)}… is not in the mandate`);
  }
  const not_evaluated = Object.keys(mandate).filter((k) => !RESERVED.includes(k));
  if (mandate.max_per_day && q.spent_today === undefined) not_evaluated.push("max_per_day (pass spent_today: the issuer keeps no record of acts)");
  return { allowed: checks.every((c) => c.ok), checks, not_evaluated };
}

/** checkMandate over every mandate of a delegation chain (credential first): allowed only when all allow it. */
export function checkMandates(mandates: Mandate[], q: ActionQuery, now = new Date()): LocalVerdict & { levels: LocalVerdict[] } {
  const levels = mandates.map((m) => checkMandate(m, q, now));
  const prefix = (i: number, s: string) => (i === 0 ? s : `delegation ${i}: ${s}`);
  return {
    allowed: levels.length > 0 && levels.every((l) => l.allowed),
    checks: levels.flatMap((l, i) => l.checks.map((c) => ({ ...c, rule: prefix(i, c.rule) }))),
    not_evaluated: [...new Set(levels.flatMap((l, i) => l.not_evaluated.map((n) => prefix(i, n))))],
    levels
  };
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
  // Offline mode is opt-in and validated here: missing anchors, clock or certificate status throws.
  const offline: ResolvedOffline | null = opts.offline === undefined ? null : resolveOffline(opts.offline);
  const client = createKyaClient(opts);
  const cacheTtl = opts.cacheTtlMs ?? 60_000;
  const maxSkew = opts.maxSkewSeconds ?? 300;
  const maxTtl = opts.maxTtlSeconds ?? 600;
  const requireBodyHash = opts.requireBodyHash ?? true;
  const cache = new Map<string, { at: number; v: Verification }>();
  const replayCache = opts.replayCache ?? null;
  if (replayCache && (typeof replayCache.seen !== "function" || !Number.isFinite(maxTtl) || maxTtl <= 0)) throw new Error("replayCache needs a seen() function and a finite, positive maxTtlSeconds: entries are kept until each request expires");

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

  /** The offline clock, checked on every use (a wrong clock makes stale evidence look fresh). */
  function offlineNow(): Date | null {
    const d = offline?.now();
    return d instanceof Date && !Number.isNaN(d.getTime()) ? d : null;
  }

  async function authenticateParts(p: { method: string; url: string; headers: Headers | Record<string, string | string[] | undefined>; body?: string | ArrayBuffer | Uint8Array | null }): Promise<KyaAuthResult> {
    const credentialId = headerOf(p.headers, KYA_HEADERS.credential);
    const created = Number(headerOf(p.headers, KYA_HEADERS.created));
    const expires = Number(headerOf(p.headers, KYA_HEADERS.expires));
    const signature = headerOf(p.headers, KYA_HEADERS.signature);
    const contentHeader = headerOf(p.headers, KYA_HEADERS.content);
    const delegationHeader = headerOf(p.headers, KYA_HEADERS.delegation);
    const document = offline ? headerOf(p.headers, KYA_HEADERS.credentialDocument) : null;
    const useOffline = offline !== null && (document !== null || !offline.issuerFallback);
    if (!credentialId || !signature || !Number.isFinite(created) || !Number.isFinite(expires)) return fail(401, "KYA_HEADERS_MISSING", `send ${KYA_HEADERS.credential}, ${KYA_HEADERS.created}, ${KYA_HEADERS.expires} and ${KYA_HEADERS.signature}`);
    const at = useOffline ? offlineNow() : new Date();
    if (!at) return fail(502, "KYA_CLOCK_INVALID", "the verifier's clock (offline.now) did not return a valid Date");
    const now = Math.floor(at.getTime() / 1000);
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

    const delegationSha256 = delegationHeader ? await sha256Hex(delegationHeader) : null;
    const text = requestText({ credentialId, method: p.method, url: p.url, created, expires, contentSha256: contentHeader, delegationSha256 });
    const once = (r: KyaAuthResult) => (r.ok && replayCache ? replayCheck(r, text, expires, at) : r);
    if (useOffline) return once(await authenticateOffline({ credentialId, document, proofHeader: headerOf(p.headers, KYA_HEADERS.principalProof), delegationHeader, text, signature, bodyState, at }));

    let v: Verification;
    try {
      v = await verification(credentialId);
    } catch (e) {
      const status = (e as { status?: number }).status;
      return status === 404 ? fail(401, "KYA_CREDENTIAL_UNKNOWN", "unknown credential_id") : fail(502, "KYA_ISSUER_UNAVAILABLE", (e as Error).message);
    }
    let delegation: KyaContext["delegation"] = null;
    if (delegationHeader) {
      if (!v.credential) return fail(403, "KYA_CREDENTIAL_NOT_ACTIVE", `credential is ${v.status}`);
      const d = await delegationOf(anchorOf(credentialId, v.agent, v.credential), delegationHeader);
      if (!d.ok) return d.result;
      delegation = d.delegation;
    }
    return once(await finish(credentialId, v, text, signature, bodyState, delegation));
  }

  /**
   * Replay cache (opt-in): runs only after the request fully verified, so a forged request cannot fill the cache
   * or burn a genuine request's key. The key is the SHA-256 of the signed request text (not of the signature, which
   * an ECDSA signer could re-randomize); it is kept until the request's own expiry, the last instant at which the
   * window would accept it again.
   */
  async function replayCheck(r: KyaAuthResult, text: string, expires: number, at: Date): Promise<KyaAuthResult> {
    let replayed: boolean;
    try {
      replayed = await (replayCache as ReplayCache).seen(await sha256Hex(text), new Date(expires * 1000), at);
    } catch (e) {
      return fail(502, "KYA_REPLAY_CACHE_UNAVAILABLE", `replay cache: ${(e as Error).message}`);
    }
    return replayed ? fail(401, "KYA_REQUEST_REPLAYED", "this signed request was already accepted; sign each request anew") : r;
  }

  const anchorOf = (credentialId: string, agent: AgentKey, credential: Pick<Credential, "mandate" | "expires_at">): DelegationAnchor => ({ credential_id: credentialId, agent: agent as DelegationAnchor["agent"], mandate: credential.mandate as DelegationAnchor["mandate"], expires_at: credential.expires_at });

  /** D-30: verifies a KYA-Delegation chain against the credential (offline, core rules). */
  async function delegationOf(anchor: DelegationAnchor, header: string, now?: Date): Promise<{ ok: true; delegation: NonNullable<KyaContext["delegation"]> } | { ok: false; result: KyaAuthResult }> {
    const no = (status: 401 | 403, error: string, message: string) => ({ ok: false as const, result: fail(status, error, message) });
    let chain: unknown;
    try {
      chain = decodeDelegationHeader(header);
    } catch (e) {
      return no(401, "KYA_DELEGATION_MALFORMED", (e as Error).message);
    }
    const r = await verifyDelegationChain({ credential: anchor, chain, now });
    if (!r.ok) return no(r.error === "KYA_DELEGATION_NOT_ALLOWED" || r.error === "KYA_DELEGATION_BROADER" ? 403 : 401, r.error, r.message);
    return { ok: true, delegation: { depth: r.depth, delegate: r.delegate, expires_at: r.expires_at, chain: chain as Delegation[], mandates: r.mandates as Mandate[] } };
  }

  /**
   * Offline (opt-in): the credential and the principal's proof came with the request. Order: shape, delegation
   * chain and request signature (cheap, reject strangers before anything else), then the principal's proof up to
   * the anchors, then the caller's certificate status. No network here.
   */
  async function authenticateOffline(p: { credentialId: string; document: string | null; proofHeader: string | null; delegationHeader: string | null; text: string; signature: string; bodyState: KyaContext["body"]; at: Date }): Promise<KyaAuthResult> {
    const o = offline as ResolvedOffline;
    if (!p.document) return fail(401, "KYA_CREDENTIAL_MISSING", `this verifier works without the issuer: send ${KYA_HEADERS.credentialDocument} and ${KYA_HEADERS.principalProof}`);
    let credential: Credential;
    try {
      credential = decodeCredentialHeader(p.document);
    } catch (e) {
      return fail(401, "KYA_CREDENTIAL_MALFORMED", (e as Error).message);
    }
    if (!credential.agent || typeof credential.agent !== "object" || typeof credential.agent.id !== "string" || !credential.mandate || typeof credential.mandate !== "object" || typeof credential.expires_at !== "string" || !credential.principal || !credential.authorized_by) return fail(401, "KYA_CREDENTIAL_MALFORMED", "KYA-Credential-Document is not a credential");
    if (credential.credential_id !== p.credentialId) return fail(401, "KYA_CREDENTIAL_MISMATCH", `${KYA_HEADERS.credentialDocument} is credential ${String(credential.credential_id)}, the request names ${p.credentialId}`);
    if (!p.proofHeader) return fail(401, "KYA_PRINCIPAL_PROOF_MISSING", `send ${KYA_HEADERS.principalProof} with ${KYA_HEADERS.credentialDocument}`);
    let proof: PrincipalProof;
    try {
      proof = decodePrincipalProofHeader(p.proofHeader);
    } catch (e) {
      return fail(401, "KYA_PRINCIPAL_PROOF_MALFORMED", (e as Error).message);
    }

    let delegation: KyaContext["delegation"] = null;
    if (p.delegationHeader) {
      const d = await delegationOf(anchorOf(p.credentialId, credential.agent, credential), p.delegationHeader, p.at);
      if (!d.ok) return d.result;
      delegation = d.delegation;
    }
    const sig = await verifySignature(delegation ? delegation.delegate : credential.agent, p.text, p.signature);
    if (!sig.ok) return fail(401, "KYA_BAD_SIGNATURE", delegation ? "signature does not match the delegate's key over the signed text" : "signature does not match the credential's agent key over the signed text");

    const presented = await verifyPresentedCredential(o, credential, proof, p.at);
    if (!presented.ok) return fail(presented.status, presented.error, presented.message);
    const status = await certificateStatusOf(o, { credential, revocation: presented.revocation }, p.at);
    if (!status.ok) return fail(status.status, status.error, status.message);

    const v: Verification = { credential_id: p.credentialId, status: "active", status_reason: null, agent: credential.agent, principal: credential.principal as Verification["principal"], credential, events: [] };
    const info: NonNullable<KyaContext["offline"]> = { issuer: credential.issuer, self_issued: credential.issuer === SELF_ISSUER, verified_at: p.at.toISOString(), evidence: status.evidence };
    return { ok: true, kya: contextOf(p.credentialId, v, sig.signer, p.bodyState, delegation, info) };
  }

  async function finish(credentialId: string, v: Verification, text: string, signature: string, bodyState: KyaContext["body"], delegation: KyaContext["delegation"] = null): Promise<KyaAuthResult> {
    const sig = await verifySignature(delegation ? delegation.delegate : v.agent, text, signature);
    if (!sig.ok) return fail(401, "KYA_BAD_SIGNATURE", delegation ? "signature does not match the delegate's key over the signed text" : "signature does not match the credential's agent key over the signed text");
    if (v.status !== "active") return fail(403, "KYA_CREDENTIAL_NOT_ACTIVE", `credential is ${v.status}${v.status_reason ? `: ${v.status_reason}` : ""}`);
    return { ok: true, kya: contextOf(credentialId, v, sig.signer, bodyState, delegation, null) };
  }

  function contextOf(credentialId: string, v: Verification, signer: string, bodyState: KyaContext["body"], delegation: KyaContext["delegation"], local: NonNullable<KyaContext["offline"]> | null): KyaContext {
    const mandate = v.credential?.mandate ?? {};
    const mandates = delegation ? delegation.mandates : [mandate];
    // Offline: every mandate at the verifier's clock, and, with a freshness policy, checkFreshAction on the evidence.
    const offlineCheck = (q: ActionQuery): LocalVerdict => {
      const at = offlineNow();
      if (!at) return { allowed: false, checks: [{ rule: "clock", ok: false, detail: "the verifier's clock (offline.now) did not return a valid Date" }], not_evaluated: [] };
      const base = delegation ? checkMandates(mandates, q, at) : checkMandate(mandate, q, at);
      const policy = (offline as ResolvedOffline).policy;
      if (!policy || !local) return base;
      const f = checkFreshAction(mandate as Parameters<typeof checkFreshAction>[0], { ...q, now: at }, { policy, evidence: local.evidence });
      const freshness = f.freshness.checks.map((c) => ({ rule: `freshness (${c.kind})`, ok: c.ok, detail: c.detail }));
      return { allowed: base.allowed && f.allowed, checks: [...base.checks, ...freshness], not_evaluated: base.not_evaluated, freshness: f.freshness };
    };
    const ctx: KyaContext = {
      credential_id: credentialId,
      agent: v.agent,
      principal: v.principal,
      status: v.status,
      mandate,
      credential: v.credential,
      signer,
      body: bodyState,
      delegation,
      ...(local ? { offline: local } : {}),
      check: (q) => (local ? offlineCheck(q) : delegation ? checkMandates(mandates, q) : checkMandate(mandate, q)),
      allowed: async (q) => {
        if (local) {
          // No issuer to ask: the local verdict, unsigned, in the issuer's shape.
          const l = offlineCheck(q);
          return { credential_id: credentialId, status: v.status, allowed: l.allowed, reason: l.allowed ? "inside every mandate (verified offline)" : "refused by the mandate or the status freshness (verified offline)", checks: l.checks.map((c) => ({ field: c.rule, ok: c.ok, detail: c.detail })), not_evaluated: l.not_evaluated, offline: true, ...(l.freshness ? { freshness: l.freshness } : {}) };
        }
        if (delegation) {
          for (let i = 1; i < mandates.length; i++) {
            const localVerdict = checkMandate(mandates[i]!, q);
            if (!localVerdict.allowed) {
              return { credential_id: credentialId, status: v.status, allowed: false, reason: `outside the mandate of delegation ${i}`, checks: localVerdict.checks.map((c) => ({ field: c.rule, ok: c.ok, detail: c.detail })), not_evaluated: localVerdict.not_evaluated, delegation_level: i };
            }
          }
        }
        return client.allowed(credentialId, q);
      }
    };
    return ctx;
  }

  /** Low level: verify a signature by a credential's agent key over a text you built yourself (used for signed responses). */
  async function verifySigned(p: { credentialId: string; text: string; signature: string; body?: KyaContext["body"] }): Promise<KyaAuthResult> {
    if (offline && !offline.issuerFallback) return fail(401, "KYA_CREDENTIAL_MISSING", "this verifier works without the issuer: a bare signature carries no credential to check");
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
