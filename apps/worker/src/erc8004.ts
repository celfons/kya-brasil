/**
 * On-chain lookup of an ERC-8004 agent's wallet. RPC endpoints come from EVM_RPC_URLS (JSON object
 * chainId → url) with public defaults for Base and Ethereum (core DEFAULT_RPC_URLS).
 */
import { type AgentKey, parseErc8004Id, resolveAgentWallet } from "@kya-br/core";
import type { AppEnv } from "./env";

function rpcUrl(env: AppEnv, chainId: number): string | undefined {
  try {
    const map = env.EVM_RPC_URLS ? (JSON.parse(env.EVM_RPC_URLS) as Record<string, string>) : {};
    return map[String(chainId)];
  } catch {
    return undefined;
  }
}

/** For erc8004 keys, returns the key with `wallet` resolved now; other kinds pass through. */
export async function withWallet(env: AppEnv, agent: AgentKey): Promise<AgentKey> {
  if (agent.kind !== "erc8004") return agent;
  const ref = parseErc8004Id(agent.id);
  const wallet = await resolveAgentWallet(ref, { rpcUrl: rpcUrl(env, ref.chainId) });
  return { ...agent, wallet };
}
