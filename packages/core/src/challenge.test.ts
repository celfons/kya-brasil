import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { base64url, challengeText, newChallenge, normalizeAgentKey, verifyAgentSignature } from "./challenge";

describe("agent key challenge", () => {
  it("EVM: signs the challenge with the wallet and verifies by address", async () => {
    const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
    const agent = normalizeAgentKey({ kind: "evm", id: account.address.toLowerCase() });
    expect(agent.id).toBe(account.address);
    const ch = newChallenge({ issuer: "https://kya.test", agent, cnpj: "11222333000181" });
    expect(ch.text).toContain(`agent: evm:${account.address}`);
    const sig = await account.signMessage({ message: ch.text });
    expect(await verifyAgentSignature(agent, ch.text, sig)).toBe(true);
    expect(await verifyAgentSignature(agent, ch.text + "x", sig)).toBe(false);
    const other = normalizeAgentKey({ kind: "evm", id: "0x0000000000000000000000000000000000000001" });
    expect(await verifyAgentSignature(other, ch.text, sig)).toBe(false);
  });

  it("Web Bot Auth: Ed25519 raw signature over the challenge text", async () => {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const agent = normalizeAgentKey({ kind: "web-bot-auth", id: base64url.encode(raw) });
    const text = challengeText({ issuer: "https://kya.test", challenge_id: "c1", agent, cnpj: "11222333000181", expires_at: "2026-10-12T00:15:00Z" });
    const sig = base64url.encode(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, new TextEncoder().encode(text))));
    expect(await verifyAgentSignature(agent, text, sig)).toBe(true);
    expect(await verifyAgentSignature(agent, text, base64url.encode(new Uint8Array(64)))).toBe(false);
  });

  it("rejects malformed keys", () => {
    expect(() => normalizeAgentKey({ kind: "evm", id: "0x123" })).toThrow(/address/);
    expect(() => normalizeAgentKey({ kind: "web-bot-auth", id: "AAAA" })).toThrow(/32 bytes/);
    expect(() => normalizeAgentKey({ kind: "solana", id: "x" })).toThrow(/kind/);
  });
});

describe("base64url padding (no backtracking regex)", () => {
  it("never leaves '=' and round-trips every length", () => {
    for (let n = 0; n < 40; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
      const s = base64url.encode(bytes);
      expect(s).not.toMatch(/[=+/]/);
      expect([...base64url.decode(s)]).toEqual([...bytes]);
    }
  });
});
