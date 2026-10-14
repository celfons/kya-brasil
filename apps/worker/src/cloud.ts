/**
 * /sign with a cloud e-CNPJ (D-28): OAuth authorization code + PKCE against the provider, then the issuer
 * signs the stored challenge through the provider's session and calls prove. What the server holds and for how
 * long: the PKCE verifier and the request ids in KV for 10 minutes (single use); the provider session only for
 * the duration of the callback, never stored. Only the stored challenge text is ever signed.
 */
import { KyaError, cloudSigner, isProviderId, newState, pkcePair, type CloudSignatureProvider } from "@kya-brasil/core";
import type { AppEnv } from "./env";
import { prove } from "./service";
import { Store } from "./store";

const STATE_TTL_SECONDS = 600;
const key = (state: string) => `cloud:state:${state}`;

interface Pending {
  provider: string;
  id: string;
  challenge_id: string;
  agent_signature: string;
  verifier: string;
}

export const callbackUrl = (origin: string) => `${origin}/sign/cloud/callback`;

/** Starts the flow: checks the request, keeps the PKCE verifier under a fresh state, returns the provider URL. */
export async function startCloudSigning(env: AppEnv, origin: string, providers: CloudSignatureProvider[], providerId: string, q: { id?: string; challenge_id?: string; agent_signature?: string; login_hint?: string }) {
  const provider = isProviderId(providerId) ? providers.find((p) => p.id === providerId) : undefined;
  if (!provider) throw new KyaError("NOT_FOUND", `no cloud provider "${providerId}" on this issuer`);
  if (!q.id || !q.challenge_id || !q.agent_signature) throw new KyaError("INVALID_INPUT", "id, challenge_id and agent_signature are required (open this from the signing link the agent sent)");
  const store = new Store(env.DB);
  const row = await store.get(q.id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (!(await store.peekChallenge(q.challenge_id, row.id))) throw new KyaError("CHALLENGE_FAILED", "challenge unknown, expired or already used; ask for a new link");
  const state = newState();
  const { verifier, challenge } = await pkcePair();
  const pending: Pending = { provider: provider.id, id: row.id, challenge_id: q.challenge_id, agent_signature: q.agent_signature, verifier };
  await env.CACHE.put(key(state), JSON.stringify(pending), { expirationTtl: STATE_TTL_SECONDS });
  return provider.authorizationUrl({ redirectUri: callbackUrl(origin), state, codeChallenge: challenge, loginHint: q.login_hint });
}

/** The provider redirected back: exchange, sign the stored challenge, issue. The state is consumed first. */
export async function finishCloudSigning(env: AppEnv, origin: string, providers: CloudSignatureProvider[], q: { code?: string; state?: string; error?: string; error_description?: string }) {
  if (!q.state) throw new KyaError("INVALID_INPUT", "missing state");
  const raw = await env.CACHE.get(key(q.state));
  await env.CACHE.delete(key(q.state));
  if (!raw) throw new KyaError("CHALLENGE_FAILED", "this authorization expired or was already used; start again from the signing link");
  const p = JSON.parse(raw) as Pending;
  if (q.error) throw new KyaError("CHALLENGE_FAILED", `the provider did not authorize: ${q.error_description ?? q.error}`);
  if (!q.code) throw new KyaError("INVALID_INPUT", "missing code");
  const provider = providers.find((x) => x.id === p.provider);
  if (!provider) throw new KyaError("NOT_FOUND", `cloud provider "${p.provider}" is no longer configured`);
  const store = new Store(env.DB);
  const row = await store.get(p.id);
  const ch = row ? await store.peekChallenge(p.challenge_id, row.id) : null;
  if (!row || !ch) throw new KyaError("CHALLENGE_FAILED", "challenge expired or already used; ask for a new link");
  const session = await provider.exchangeCode({ code: q.code, redirectUri: callbackUrl(origin), codeVerifier: p.verifier });
  let ecnpj_signature: string;
  try {
    const signer = await cloudSigner(session);
    ecnpj_signature = await signer.sign(ch.text);
  } finally {
    await session.close?.().catch(() => undefined);
  }
  return prove(env, origin, p.id, { challenge_id: p.challenge_id, agent_signature: p.agent_signature, ecnpj_signature });
}
