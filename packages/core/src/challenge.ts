/**
 * Proof of key possession by the agent. The issuer hands out a one-time challenge; the agent
 * signs it with its key. Three key kinds:
 *   evm           EIP-191 personal_sign over the challenge text; address recovered and compared
 *   web-bot-auth  Ed25519 (RFC 9421 key material) raw signature over the challenge bytes
 *   erc8004       EIP-191 by the agent's on-chain agentWallet (resolved by the caller, see erc8004.ts)
 * The challenge text binds agent key, CNPJ, issuer and expiry, so a signature cannot be replayed
 * for another company or another issuer.
 */
import { verifyMessage, getAddress, isAddress } from "viem";
import { type AgentKey, KyaError } from "./types";
import { parseErc8004Id } from "./erc8004";

export const CHALLENGE_TTL_SECONDS = 900;

export interface Challenge {
  challenge_id: string;
  text: string;
  expires_at: string;
}

/** Drops trailing "=" padding with a linear scan (no regex). */
const stripPadding = (s: string) => {
  let end = s.length;
  while (end > 0 && s[end - 1] === "=") end--;
  return s.slice(0, end);
};
const b64u = (bytes: Uint8Array) => stripPadding(btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_"));
const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), (c) => c.charCodeAt(0));

export function normalizeAgentKey(input: { kind?: unknown; id?: unknown }): AgentKey {
  if (input.kind === "evm") {
    if (typeof input.id !== "string" || !isAddress(input.id)) throw new KyaError("INVALID_INPUT", "agent.id must be a 0x EVM address for kind evm");
    return { kind: "evm", id: getAddress(input.id) };
  }
  if (input.kind === "web-bot-auth") {
    if (typeof input.id !== "string") throw new KyaError("INVALID_INPUT", "agent.id must be the Ed25519 public key (base64url, 32 bytes) for kind web-bot-auth");
    let raw: Uint8Array;
    try {
      raw = unb64u(input.id);
    } catch {
      throw new KyaError("INVALID_INPUT", "agent.id is not base64url");
    }
    if (raw.length !== 32) throw new KyaError("INVALID_INPUT", "agent.id must decode to 32 bytes");
    return { kind: "web-bot-auth", id: b64u(raw) };
  }
  if (input.kind === "erc8004") {
    const { id } = parseErc8004Id(input.id);
    return { kind: "erc8004", id };
  }
  throw new KyaError("INVALID_INPUT", "agent.kind must be evm, web-bot-auth or erc8004");
}

/** The exact text the agent signs. Line-based so wallets show it readably. */
export function challengeText(p: { issuer: string; challenge_id: string; agent: AgentKey; cnpj: string; expires_at: string }): string {
  return [
    "KYA Brasil: prove this agent key acts for a company",
    `issuer: ${p.issuer}`,
    `challenge: ${p.challenge_id}`,
    `agent: ${p.agent.kind}:${p.agent.id}`,
    `cnpj: ${p.cnpj}`,
    `expires: ${p.expires_at}`
  ].join("\n");
}

export function newChallenge(p: { issuer: string; agent: AgentKey; cnpj: string; now?: Date }): Challenge {
  const now = p.now ?? new Date();
  const challenge_id = crypto.randomUUID();
  const expires_at = new Date(now.getTime() + CHALLENGE_TTL_SECONDS * 1000).toISOString();
  return { challenge_id, expires_at, text: challengeText({ issuer: p.issuer, challenge_id, agent: p.agent, cnpj: p.cnpj, expires_at }) };
}

/** True when `signature` is the agent key's signature over `text`. Never throws on a bad signature. */
export async function verifyAgentSignature(agent: AgentKey, text: string, signature: string): Promise<boolean> {
  try {
    if (agent.kind === "evm" || agent.kind === "erc8004") {
      if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) return false;
      const address = agent.kind === "evm" ? agent.id : agent.wallet;
      if (!address) return false; // erc8004 without a resolved wallet: nothing to compare against
      return await verifyMessage({ address: address as `0x${string}`, message: text, signature: signature as `0x${string}` });
    }
    const raw = unb64u(agent.id);
    const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
    const sig = unb64u(signature);
    if (sig.length !== 64) return false;
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, new TextEncoder().encode(text));
  } catch {
    return false;
  }
}

export const base64url = { encode: b64u, decode: unb64u };
