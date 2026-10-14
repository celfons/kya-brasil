import { describe, expect, it } from "vitest";
import { encodeAbiParameters, encodeFunctionData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { normalizeAgentKey, verifyAgentSignature } from "./challenge.js";
import { ERC8004_IDENTITY_ABI, mockTransport, parseErc8004Id, resolveAgentWallet } from "./erc8004.js";

const OWNER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const WALLET_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const WALLET = privateKeyToAccount(WALLET_PK).address;
const sel = (name: "getAgentWallet" | "ownerOf") => encodeFunctionData({ abi: ERC8004_IDENTITY_ABI, functionName: name, args: [1n] }).slice(0, 10);
const addr = (a: string) => encodeAbiParameters([{ type: "address" }], [a as `0x${string}`]);

describe("ERC-8004 identities", () => {
  it("parses and normalizes the id", () => {
    const p = parseErc8004Id("eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42");
    expect(p).toMatchObject({ chainId: 8453, registry: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432", agentId: 42n });
    expect(normalizeAgentKey({ kind: "erc8004", id: "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42" }).id).toBe("eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42");
    expect(() => parseErc8004Id("eip155:8453:nope:1")).toThrow(/erc8004/);
    expect(() => parseErc8004Id("eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432")).toThrow(/erc8004/);
  });

  it("resolves agentWallet, falls back to ownerOf, reports a missing token", async () => {
    const ref = parseErc8004Id("eip155:1:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:1");
    expect(await resolveAgentWallet(ref, { transport: mockTransport({ [sel("ownerOf")]: addr(OWNER), [sel("getAgentWallet")]: addr(WALLET) }) })).toBe(WALLET);
    expect(await resolveAgentWallet(ref, { transport: mockTransport({ [sel("ownerOf")]: addr(OWNER) }) })).toBe(OWNER);
    expect(await resolveAgentWallet(ref, { transport: mockTransport({ [sel("ownerOf")]: addr(OWNER), [sel("getAgentWallet")]: addr("0x0000000000000000000000000000000000000000") }) })).toBe(OWNER);
    await expect(resolveAgentWallet(ref, { transport: mockTransport({}) })).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("verifies the challenge signature against the resolved wallet only", async () => {
    const text = "KYA Brasil: prove this agent key acts for a company\nchallenge: x";
    const sig = await privateKeyToAccount(WALLET_PK).signMessage({ message: text });
    const agent = { kind: "erc8004" as const, id: "eip155:1:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:1" };
    expect(await verifyAgentSignature({ ...agent, wallet: WALLET }, text, sig)).toBe(true);
    expect(await verifyAgentSignature({ ...agent, wallet: OWNER }, text, sig)).toBe(false);
    expect(await verifyAgentSignature(agent, text, sig)).toBe(false);
  });
});
