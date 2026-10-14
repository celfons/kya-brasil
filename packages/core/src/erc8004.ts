/**
 * ERC-8004 (Trustless Agents) identities, read-only. An agent registered in an Identity Registry
 * (an ERC-721 token) is addressed as
 *
 *   eip155:<chainId>:<identityRegistry>:<agentId>
 *
 * and signs the challenge with its `agentWallet` (the registry's reserved metadata key; defaults to the
 * token owner). The issuer resolves that wallet on chain at registration, at proof and in the daily
 * review, so a credential never outlives a wallet change. Nothing is written on chain in this version.
 */
import { createPublicClient, custom, getAddress, http, isAddress, type Transport } from "viem";
import { KyaError } from "./types.js";

/** Canonical registries (deterministic deployment, same address on every chain of its kind). */
export const ERC8004_IDENTITY_REGISTRIES: Record<number, `0x${string}`> = {
  // mainnets (Ethereum, Base, Arbitrum One, Optimism, Polygon PoS, ...)
  1: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
  8453: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
  42161: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
  10: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
  137: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
  // testnets (Ethereum Sepolia, Base Sepolia, ...)
  11155111: "0x8004A818BFB912233c491871b3d84c89A494BD9e",
  84532: "0x8004A818BFB912233c491871b3d84c89A494BD9e"
};

export const DEFAULT_RPC_URLS: Record<number, string> = {
  1: "https://ethereum-rpc.publicnode.com",
  8453: "https://mainnet.base.org",
  84532: "https://sepolia.base.org",
  11155111: "https://ethereum-sepolia-rpc.publicnode.com"
};

export const ERC8004_IDENTITY_ABI = [
  { type: "function", name: "getAgentWallet", stateMutability: "view", inputs: [{ name: "agentId", type: "uint256" }], outputs: [{ type: "address" }] },
  { type: "function", name: "ownerOf", stateMutability: "view", inputs: [{ name: "tokenId", type: "uint256" }], outputs: [{ type: "address" }] },
  { type: "function", name: "tokenURI", stateMutability: "view", inputs: [{ name: "tokenId", type: "uint256" }], outputs: [{ type: "string" }] }
] as const;

export interface Erc8004Id {
  chainId: number;
  registry: `0x${string}`;
  agentId: bigint;
}

/** Parses and normalizes `eip155:<chainId>:<registry>:<agentId>`; throws INVALID_INPUT otherwise. */
export function parseErc8004Id(id: unknown): Erc8004Id & { id: string } {
  if (typeof id !== "string") throw new KyaError("INVALID_INPUT", "agent.id must be eip155:<chainId>:<identityRegistry>:<agentId> for kind erc8004");
  const m = /^eip155:(\d{1,10}):(0x[0-9a-fA-F]{40}):(\d{1,78})$/.exec(id.trim());
  if (!m) throw new KyaError("INVALID_INPUT", "agent.id must be eip155:<chainId>:<identityRegistry>:<agentId> for kind erc8004");
  const chainId = Number(m[1]);
  if (!isAddress(m[2]!)) throw new KyaError("INVALID_INPUT", "identityRegistry is not an address");
  const registry = getAddress(m[2]!);
  const agentId = BigInt(m[3]!);
  return { chainId, registry, agentId, id: `eip155:${chainId}:${registry}:${agentId.toString()}` };
}

export interface ResolveOptions {
  /** RPC URL for the chain; defaults to DEFAULT_RPC_URLS[chainId]. */
  rpcUrl?: string;
  /** Test hook: a viem transport (e.g. custom({ request })) instead of HTTP. */
  transport?: Transport;
}

/**
 * The wallet that signs for the agent: `getAgentWallet(agentId)` (ERC-8004 reserved metadata), falling
 * back to `ownerOf(agentId)` on registries without the getter. Throws NOT_FOUND when the token does not
 * exist and UPSTREAM_ERROR when the chain cannot be read.
 */
export async function resolveAgentWallet(ref: Erc8004Id, opts: ResolveOptions = {}): Promise<`0x${string}`> {
  const url = opts.rpcUrl ?? DEFAULT_RPC_URLS[ref.chainId];
  if (!opts.transport && !url) throw new KyaError("INVALID_INPUT", `no RPC configured for chain ${ref.chainId}`);
  const client = createPublicClient({ transport: opts.transport ?? http(url, { timeout: 8000, retryCount: 1 }) });
  const read = (functionName: "getAgentWallet" | "ownerOf") => client.readContract({ address: ref.registry, abi: ERC8004_IDENTITY_ABI, functionName, args: [ref.agentId] });
  try {
    const owner = await read("ownerOf"); // reverts for a token that does not exist
    let wallet: `0x${string}` = owner;
    try {
      const w = await read("getAgentWallet");
      if (w && w !== "0x0000000000000000000000000000000000000000") wallet = w;
    } catch {
      // registry without getAgentWallet (older deployments): the owner signs
    }
    return getAddress(wallet);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/revert|nonexistent|invalid token|ERC721/i.test(msg)) throw new KyaError("NOT_FOUND", `agent ${ref.agentId} not found in ${ref.registry} on chain ${ref.chainId}`);
    throw new KyaError("UPSTREAM_ERROR", `could not read chain ${ref.chainId}: ${msg.split("\n")[0]}`);
  }
}

/** Test helper: a viem transport answering eth_call from a map of function selector → ABI-encoded result. */
export function mockTransport(answers: Record<string, string | Error>): Transport {
  return custom({
    request: async ({ method, params }: { method: string; params?: unknown[] }) => {
      if (method === "eth_chainId") return "0x1";
      if (method !== "eth_call") throw new Error(`unexpected ${method}`);
      const data = ((params?.[0] as { data?: string })?.data ?? "").slice(0, 10);
      const a = answers[data];
      if (a === undefined) throw new Error("execution reverted");
      if (a instanceof Error) throw a;
      return a;
    }
  });
}
