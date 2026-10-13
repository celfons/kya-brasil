/**
 * @kya-brasil/agent-tools
 *
 * Two sides of KYA Brasil, one client:
 *
 *   Verifier (you receive an action from someone else's agent):
 *     const kya = createKyaClient({ privateKey });           // wallet optional: free verification works without it
 *     const v = await kya.verify(credentialId);               // free, 50/day per IP
 *     const ok = await kya.allowed(credentialId, { action: "pay", amount: 80, currency: "USDC", counterparty: "33000167000101" }); // $0.01
 *     tools for your agent framework: toOpenAI(kya), toVercelAI(kya, { tool, jsonSchema }), toLangChain(kya, tool), toAnthropic(kya)
 *
 *   Company (you give your own agent a credential):
 *     const reg = await kya.register({ agent: { kind: "evm", id: address }, cnpj, mandate });   // $0.50, returns a challenge
 *     const agent_signature = await signChallengeWithEvmKey(agentPrivateKey, reg.challenge.text);
 *     const ecnpj_signature = await signWithECnpj({ certificatePem, privateKeyPem, chainPem }, reg.challenge.text);
 *     const issued = await kya.prove(reg.credential_id, { challenge_id: reg.challenge.id, agent_signature, ecnpj_signature });
 */
import { x402Client } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";
import { wrapFetchWithPayment } from "@x402/fetch";
import { privateKeyToAccount } from "viem/accounts";
import * as pkijs from "pkijs";
import { toBase64Url } from "./base64url";

export const DEFAULT_BASE_URL = "https://kya-br-agents.marcelfons.workers.dev";

export interface KyaOptions {
  /** Service origin; defaults to production. */
  baseUrl?: string;
  /** Private key of the paying wallet (USDC on Base). Without it paid calls throw PAYMENT_REQUIRED. */
  privateKey?: `0x${string}`;
  /** Internal channel key (platform partners, billed by invoice); bypasses x402. */
  internalKey?: string;
  fetch?: typeof fetch;
}

/** erc8004: id is eip155:<chainId>:<identityRegistry>:<agentId>; the on-chain agentWallet signs (credential.agent.wallet). */
export type AgentKey = { kind: "evm" | "web-bot-auth" | "erc8004"; id: string; wallet?: `0x${string}` };
export type CredentialStatus = "pending" | "active" | "suspended" | "revoked" | "expired";

export interface Mandate {
  actions?: string[];
  max_per_operation?: { amount: number; currency: string };
  max_per_day?: { amount: number; currency: string };
  currencies?: string[];
  counterparties?: string[];
  valid_from?: string;
  valid_until?: string;
  [k: string]: unknown;
}

export interface Attestation { algorithm: string; key_id: string; sha256: string; signed_at: string; signature: string; verify_url?: string }

export interface Credential {
  credential_id: string;
  version: number;
  agent: AgentKey;
  principal: { cnpj: string; legal_name?: string; registration_status?: string };
  authorized_by: { method: string; certificate_sha256: string; certificate_subject: string; issuer: string; signed_at: string };
  mandate: Mandate;
  /** Informative; null when the issuer has no KYB source. */
  kyb_snapshot: Record<string, unknown> | null;
  status: CredentialStatus;
  issued_at: string;
  expires_at: string;
  issuer: string;
  verify_url: string;
  revocation_url: string;
  attestation?: Attestation;
  [k: string]: unknown;
}

export interface Verification {
  credential_id: string;
  status: CredentialStatus;
  status_reason: string | null;
  agent: AgentKey;
  principal: { cnpj: string; cnpj_formatted: string; legal_name: string | null };
  credential: Credential | null;
  events: { ts: string; event: string; reason: string | null; actor: string }[];
  attestation?: Attestation;
  [k: string]: unknown;
}

export interface ActionQuery { action?: string; amount?: number; currency?: string; counterparty?: string; spent_today?: number }

export interface Verdict {
  credential_id: string;
  status: CredentialStatus;
  allowed: boolean;
  reason: string;
  checks: { field: string; ok: boolean; detail?: string }[];
  not_evaluated: string[];
  attestation?: Attestation;
  [k: string]: unknown;
}

export interface Registration {
  credential_id: string;
  agent: AgentKey;
  principal: { cnpj: string; cnpj_formatted: string };
  mandate: Mandate;
  challenge: { id: string; text: string; expires_at: string };
  next: { en: string; pt: string };
  mandate_schema: string;
}

export interface Proof { challenge_id: string; agent_signature: string; ecnpj_signature: string }

export interface ActInput {
  action: string;
  amount?: number;
  currency?: string;
  counterparty?: string;
  reference?: string;
  content_sha256?: string;
  registered_by?: "counterparty" | "agent";
  registrant?: string;
  agent_signature?: string;
}

export interface ActReceipt {
  act_id: string;
  credential_id: string;
  status: CredentialStatus;
  allowed: boolean;
  reason: string;
  act: ActInput & { agent_signed: boolean };
  checks: { rule: string; ok: boolean; detail?: string }[];
  not_evaluated: string[];
  spent_today_registered_before: { currency: string; amount: number } | null;
  spent_today_registered_after: { currency: string; amount: number } | null;
  registered_at: string;
  receipt_url: string;
  attestation?: Attestation;
  [k: string]: unknown;
}

export class KyaError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status: number
  ) {
    super(message);
    this.name = "KyaError";
  }
}

function buildFetch(opts: KyaOptions): typeof fetch {
  const base = opts.fetch ?? fetch;
  if (!opts.privateKey) return base;
  const client = new x402Client();
  registerExactEvmScheme(client, { signer: toClientEvmSigner(privateKeyToAccount(opts.privateKey)) });
  return wrapFetchWithPayment(base, client) as typeof fetch;
}

export interface KyaClient {
  baseUrl: string;
  /** Free (50/day per IP): current credential, live status and event history. */
  verify(credentialId: string): Promise<Verification>;
  /** Free: active credentials held by an agent key. */
  verifyByKey(agent: AgentKey): Promise<{ agent: AgentKey; credentials: Verification[] }>;
  /** $0.01, no limit: same as verify plus a signed receipt of the verification. */
  verified(credentialId: string): Promise<Verification & { verification: Record<string, unknown> }>;
  /** $0.01: signed verdict, is this action inside the mandate and is the credential active? */
  allowed(credentialId: string, q: ActionQuery): Promise<Verdict>;
  /** $0.50: register an agent for a company; returns the challenge both parties sign. */
  register(input: { agent: AgentKey; cnpj: string; mandate: Mandate }): Promise<Registration>;
  /** Free: send both signatures; the credential is issued if the e-CNPJ is valid and not revoked, the CNPJ matches and the company is ATIVA. */
  prove(credentialId: string, proof: Proof): Promise<{ credential: Credential; kyb_warnings: string[] }>;
  /** $0.10: renewal challenge (then renewProve). */
  renew(credentialId: string): Promise<{ credential_id: string; challenge: { id: string; text: string; expires_at: string } }>;
  renewProve(credentialId: string, proof: Proof): Promise<{ credential: Credential; kyb_warnings: string[] }>;
  /** Free: the company revokes at once. signed_text must be "KYA Brasil: revoke <id>\n<nonce>", signed with the e-CNPJ. */
  revoke(credentialId: string, input: { signed_text: string; ecnpj_signature: string; reason?: string }): Promise<{ credential_id: string; status: "revoked" }>;
  /** $0.02: register what the agent did (you accepted it); mandate re-checked with today's registered acts; signed receipt. */
  registerAct(credentialId: string, act: ActInput): Promise<ActReceipt>;
  /** Free: a registered act and its receipt, by act_id. */
  act(actId: string): Promise<ActReceipt>;
  /** Free: the exact text the agent signs for an act (optional agent_signature). */
  actText(credentialId: string, act: ActInput): Promise<{ credential_id: string; agent: AgentKey; text: string }>;
  /** Free, company only: the trail of an agent's acts, request signed with the e-CNPJ over actsExportText(id). */
  exportActs(credentialId: string, input: { signed_text: string; ecnpj_signature: string; since?: string }): Promise<{ credential_id: string; since: string; count: number; acts: Record<string, unknown>[] }>;
  /** Free: credentials revoked since a date (default 30 days). */
  revocations(since?: string): Promise<{ since: string; count: number; revocations: { credential_id: string; revoked_at: string; reason: string | null }[] }>;
  /** Tool definitions for agent frameworks (verifier side). */
  tools: KyaTool[];
  execute(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export interface JsonSchema { type: "object"; properties: Record<string, Record<string, unknown>>; required?: string[]; additionalProperties?: boolean }
export interface KyaTool { name: string; description: string; priceUsd: number; parameters: JsonSchema; execute: (args: Record<string, unknown>) => Promise<Record<string, unknown>> }

export function createKyaClient(opts: KyaOptions = {}): KyaClient {
  const baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
  const plain = opts.fetch ?? fetch;
  const paying = buildFetch(opts);

  async function call<T>(method: "GET" | "POST", path: string, body?: unknown, paid = false, priceUsd = 0): Promise<T> {
    const internal = paid && !!opts.internalKey;
    const url = `${baseUrl}${internal ? path.replace(/^\/v1\//, "/internal/v1/") : path}`;
    const headers: Record<string, string> = { accept: "application/json" };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (internal) headers["x-internal-key"] = opts.internalKey!;
    const res = await (paid && !internal ? paying : plain)(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (res.status === 402) throw new KyaError("PAYMENT_REQUIRED", `${method} ${path} costs $${priceUsd.toFixed(2)} USDC; pass privateKey (wallet with USDC on Base) to pay automatically`, 402);
    if (!res.ok) throw new KyaError(String(json.error ?? "UPSTREAM_ERROR"), String(json.message ?? `HTTP ${res.status}`), res.status);
    return json as T;
  }
  const q = (o: Record<string, unknown>) => {
    const s = new URLSearchParams();
    for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== "") s.set(k, String(v));
    const str = s.toString();
    return str ? `?${str}` : "";
  };

  const client: KyaClient = {
    baseUrl,
    verify: (id) => call("GET", `/v1/agents/${encodeURIComponent(id)}`),
    verifyByKey: (agent) => call("GET", `/v1/agents/by-key${q({ kind: agent.kind, id: agent.id })}`),
    verified: (id) => call("GET", `/v1/agents/${encodeURIComponent(id)}/verified`, undefined, true, 0.01),
    allowed: (id, a) => call("GET", `/v1/agents/${encodeURIComponent(id)}/allowed${q(a as Record<string, unknown>)}`, undefined, true, 0.01),
    register: (input) => call("POST", "/v1/agents", input, true, 0.5),
    prove: (id, proof) => call("POST", `/v1/agents/${encodeURIComponent(id)}/prove`, proof),
    renew: (id) => call("POST", `/v1/agents/${encodeURIComponent(id)}/renew`, {}, true, 0.1),
    renewProve: (id, proof) => call("POST", `/v1/agents/${encodeURIComponent(id)}/renew/prove`, proof),
    revoke: (id, input) => call("POST", `/v1/agents/${encodeURIComponent(id)}/revoke`, input),
    revocations: (since) => call("GET", `/v1/revocations${q({ since })}`),
    registerAct: (id, act) => call("POST", `/v1/agents/${encodeURIComponent(id)}/acts`, act, true, 0.02),
    act: (actId) => call("GET", `/v1/acts/${encodeURIComponent(actId)}`),
    actText: (id, act) => call("POST", `/v1/agents/${encodeURIComponent(id)}/acts/text`, act),
    exportActs: (id, input) => call("POST", `/v1/agents/${encodeURIComponent(id)}/acts/export`, input),
    tools: [],
    execute: async (name, args) => {
      const t = client.tools.find((x) => x.name === name);
      if (!t) throw new KyaError("NOT_FOUND", `unknown tool ${name}`, 404);
      return t.execute(args);
    }
  };

  const ID = { type: "string", description: "credential_id of the agent's KYA Brasil credential (the agent sends it with its request)." };
  client.tools = [
    {
      name: "kya_verify", priceUsd: 0,
      description: "Free. Is this AI agent credentialed by a Brazilian company? Returns the credential (company CNPJ and name, mandate, KYB snapshot), its live status (active, suspended, revoked, expired) and history. Give credential_id, or the agent key (kind + id) to look it up.",
      parameters: { type: "object", properties: { credential_id: ID, kind: { type: "string", enum: ["evm", "web-bot-auth", "erc8004"] }, id: { type: "string", description: "0x address, base64url Ed25519 key, or eip155:<chainId>:<registry>:<agentId>" } }, additionalProperties: false },
      execute: async (a) => (a.credential_id ? client.verify(String(a.credential_id)) : client.verifyByKey({ kind: a.kind as AgentKey["kind"], id: String(a.id) })) as Promise<Record<string, unknown>>
    },
    {
      name: "kya_check_action", priceUsd: 0.01,
      description: "Signed verdict ($0.01): may this agent perform this action (action, amount, currency, counterparty) under its company mandate, and is the credential active right now? Use before accepting an order, a payment or a signature from an agent.",
      parameters: { type: "object", properties: { credential_id: ID, action: { type: "string" }, amount: { type: "number" }, currency: { type: "string" }, counterparty: { type: "string", description: "Your CNPJ, domain or wallet address" }, spent_today: { type: "number" } }, required: ["credential_id"], additionalProperties: false },
      execute: async (a) => client.allowed(String(a.credential_id), { action: a.action as string, amount: a.amount as number, currency: a.currency as string, counterparty: a.counterparty as string, spent_today: a.spent_today as number }) as Promise<Record<string, unknown>>
    },
    {
      name: "kya_register_act", priceUsd: 0.02,
      description: "Register an action you accepted from an agent ($0.02): the issuer re-checks the mandate including everything registered today by anyone (so daily ceilings hold across counterparties) and returns a signed receipt, your proof of what the agent could and did do. Denied acts are recorded too.",
      parameters: { type: "object", properties: { credential_id: ID, action: { type: "string" }, amount: { type: "number" }, currency: { type: "string" }, counterparty: { type: "string", description: "You: CNPJ, domain or wallet" }, reference: { type: "string" }, content_sha256: { type: "string" } }, required: ["credential_id", "action"], additionalProperties: false },
      execute: async (a) => { const { credential_id, ...act } = a; return client.registerAct(String(credential_id), act as unknown as ActInput) as unknown as Promise<Record<string, unknown>>; }
    },
    {
      name: "kya_verify_paid", priceUsd: 0.01,
      description: "Same as kya_verify without the daily limit, plus a signed receipt of the verification ($0.01).",
      parameters: { type: "object", properties: { credential_id: ID }, required: ["credential_id"], additionalProperties: false },
      execute: async (a) => client.verified(String(a.credential_id)) as Promise<Record<string, unknown>>
    }
  ];
  return client;
}

// --- Adapters (no framework dependency: you pass the framework's constructors in) ---

export function toOpenAI(kya: KyaClient): { type: "function"; function: { name: string; description: string; parameters: JsonSchema } }[] {
  return kya.tools.map((t) => ({ type: "function" as const, function: { name: t.name, description: t.description, parameters: t.parameters } }));
}
export function toVercelAI<T>(kya: KyaClient, ai: { tool: (def: { description: string; parameters: unknown; execute: (args: Record<string, unknown>) => Promise<unknown> }) => T; jsonSchema: (schema: JsonSchema) => unknown }): Record<string, T> {
  return Object.fromEntries(kya.tools.map((t) => [t.name, ai.tool({ description: t.description, parameters: ai.jsonSchema(t.parameters), execute: (args) => t.execute(args) })]));
}
export function toLangChain<T>(kya: KyaClient, tool: (fn: (args: Record<string, unknown>) => Promise<string>, def: { name: string; description: string; schema: JsonSchema }) => T): T[] {
  return kya.tools.map((t) => tool(async (args) => JSON.stringify(await t.execute(args)), { name: t.name, description: t.description, schema: t.parameters }));
}
export function toAnthropic(kya: KyaClient): { name: string; description: string; input_schema: JsonSchema }[] {
  return kya.tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.parameters }));
}

// --- Signing the challenge (company side) ---

/** EIP-191 personal_sign of the challenge text with the agent's EVM key (hex signature). */
export async function signChallengeWithEvmKey(privateKey: `0x${string}`, text: string): Promise<string> {
  return privateKeyToAccount(privateKey).signMessage({ message: text });
}


/** Raw Ed25519 signature (base64url) of the challenge text with the agent's Web Bot Auth key (PKCS#8 base64 or CryptoKey). */
export async function signChallengeWithEd25519(privateKey: CryptoKey | string, text: string): Promise<string> {
  const key = typeof privateKey === "string" ? await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(privateKey), (c) => c.charCodeAt(0)), { name: "Ed25519" }, false, ["sign"]) : privateKey;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(text)));
  return toBase64Url(sig);
}

export interface ECnpjMaterial {
  /** The e-CNPJ certificate, PEM. */
  certificatePem: string;
  /** Its private key, PEM (PKCS#8). From an A1 .pfx: `openssl pkcs12 -in cert.pfx -nocerts -nodes | openssl pkcs8 -topk8 -nocrypt`. */
  privateKeyPem: string;
  /** Intermediate AC certificates, PEM (the chain up to the ICP-Brasil root). From the .pfx: `openssl pkcs12 -in cert.pfx -cacerts -nokeys`. */
  chainPem?: string[];
}

const pemToDer = (pem: string) => Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")), (c) => c.charCodeAt(0)).buffer as ArrayBuffer;
const pemBlocks = (pem: string) => [...pem.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)].map((m) => m[0]);

/**
 * Detached CMS/PKCS#7 SignedData (base64 DER) over the challenge text, signed with the company's e-CNPJ.
 * Includes the certificate and the intermediate chain so the issuer can validate it against the ICP-Brasil roots.
 * Works with A1 certificates (file). A3 (token or smart card) must sign through the vendor's software.
 */
export async function signWithECnpj(material: ECnpjMaterial, text: string): Promise<string> {
  pkijs.setEngine("kya-agent-tools", new pkijs.CryptoEngine({ name: "kya-agent-tools", crypto: globalThis.crypto as Crypto }));
  const leaf = pkijs.Certificate.fromBER(pemToDer(material.certificatePem));
  const chain = (material.chainPem ?? []).flatMap(pemBlocks).map((p) => pkijs.Certificate.fromBER(pemToDer(p)));
  const der = pemToDer(material.privateKeyPem);
  const algo = leaf.subjectPublicKeyInfo.algorithm.algorithmId === "1.2.840.10045.2.1" ? { name: "ECDSA", namedCurve: "P-256" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  const key = await crypto.subtle.importKey("pkcs8", der, algo, false, ["sign"]);
  const signed = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: "1.2.840.113549.1.7.1" }),
    signerInfos: [new pkijs.SignerInfo({ version: 1, sid: new pkijs.IssuerAndSerialNumber({ issuer: leaf.issuer, serialNumber: leaf.serialNumber }) })],
    certificates: [leaf, ...chain]
  });
  await signed.sign(key, 0, "SHA-256", new TextEncoder().encode(text).buffer as ArrayBuffer);
  const ci = new pkijs.ContentInfo({ contentType: "1.2.840.113549.1.7.2", content: signed.toSchema(true) });
  const bytes = new Uint8Array(ci.toSchema().toBER(false));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** The text the company signs to read its agent's trail of acts. */
export function actsExportText(credentialId: string, nonce: string = crypto.randomUUID()): string {
  return `KYA Brasil: acts ${credentialId}\n${nonce}`;
}

/** The text the company signs to revoke a credential. */
export function revocationText(credentialId: string, nonce: string = crypto.randomUUID()): string {
  return `KYA Brasil: revoke ${credentialId}\n${nonce}`;
}

// --- Local verification of a credential or a signed answer (no network once you hold the key) ---

/**
 * Key order of the canonical JSON: UTF-16 code units, exactly what a comparator-less sort() does. Not
 * localeCompare: a locale-dependent order would change the signed bytes between machines and break every
 * signature already issued.
 */
function byCodeUnit(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function canonicalize(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  const o = v as Record<string, unknown>;
  const members = Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort(byCodeUnit)
    .map((k) => JSON.stringify(k) + ":" + canonicalize(o[k]));
  return "{" + members.join(",") + "}";
}

export interface VerifyResult { valid: boolean; reason?: string; key_id?: string; signed_at?: string }

/**
 * Verifies the Ed25519 attestation of a credential or a signed answer: recomputes the SHA-256 of the
 * canonical JSON (without attestation and receipt) and checks the signature with the issuer's key
 * (fetched from /.well-known/kya.json unless `publicJwk` is given). This proves the document was issued
 * by KYA Brasil and not modified; the live status still comes from verify().
 */
export async function verifyAttestation(doc: Record<string, unknown>, opts: { baseUrl?: string; publicJwk?: JsonWebKey; fetch?: typeof fetch } = {}): Promise<VerifyResult> {
  const att = doc.attestation as Partial<Attestation> | undefined;
  if (!att || att.algorithm !== "ed25519" || !att.sha256 || !att.signed_at || !att.signature || !att.key_id) return { valid: false, reason: "no ed25519 attestation in the document" };
  let jwk = opts.publicJwk;
  if (!jwk) {
    const base = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    const keys = (await (await (opts.fetch ?? fetch)(`${base}/.well-known/kya.json`)).json()) as { keys?: { key_id: string; jwk: JsonWebKey }[] };
    jwk = keys.keys?.find((k) => k.key_id === att.key_id)?.jwk;
    if (!jwk) return { valid: false, reason: `key ${att.key_id} not published by ${base}`, key_id: att.key_id, signed_at: att.signed_at };
  }
  const { attestation: _a, receipt: _r, ...payload } = doc;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(payload)));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (hex !== att.sha256) return { valid: false, reason: "content hash mismatch: the document was modified", key_id: att.key_id, signed_at: att.signed_at };
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, true, ["verify"]);
  const sig = Uint8Array.from(atob(att.signature), (c) => c.charCodeAt(0));
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, new TextEncoder().encode(`${hex}\n${att.signed_at}`));
  return ok ? { valid: true, key_id: att.key_id, signed_at: att.signed_at } : { valid: false, reason: "signature does not verify", key_id: att.key_id, signed_at: att.signed_at };
}
export * from "./auth";
