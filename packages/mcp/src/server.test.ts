import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { privateKeyToAccount } from "viem/accounts";
import { encodeDelegationHeader, prepareDelegation, validateMandate } from "@kya-brasil/core";
import { createKyaMcpServer } from "./server.js";

const CRED = "6d0b1c2e-1111-4222-8333-444455556666";
const ROOT = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const SUB = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

async function connect(fetchImpl?: typeof fetch) {
  const { server } = createKyaMcpServer({ baseUrl: "https://kya.test", fetch: fetchImpl });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

const text = (r: unknown) => JSON.parse((r as { content: { text: string }[] }).content[0]!.text);

describe("KYA Brasil MCP server", () => {
  it("starts without any key and lists every tool with a description", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["kya_about", "kya_check_action", "kya_check_mandate", "kya_revocations", "kya_sign_link", "kya_validate_mandate", "kya_verify", "kya_verify_credential_offline", "kya_verify_delegation", "kya_verify_paid"]);
    for (const t of tools) expect(t.description!.length).toBeGreaterThan(60);
  });

  it("checks an action against a mandate offline", async () => {
    const client = await connect();
    const mandate = { actions: ["order"], max_per_operation: { amount: 100, currency: "BRL" }, counterparties: ["*.beta.com.br"] };
    const ok = text(await client.callTool({ name: "kya_check_mandate", arguments: { mandate, action: "order", amount: 80, currency: "BRL", counterparty: "shop.beta.com.br" } }));
    expect(ok.allowed).toBe(true);
    const no = text(await client.callTool({ name: "kya_check_mandate", arguments: { mandate, action: "order", amount: 150, currency: "BRL" } }));
    expect(no.allowed).toBe(false);
  });

  it("validates a mandate and refuses a card number", async () => {
    const client = await connect();
    expect(text(await client.callTool({ name: "kya_validate_mandate", arguments: { mandate: { actions: ["pay", "pay"] } } })).mandate.actions).toEqual(["pay"]);
    const bad = await client.callTool({ name: "kya_validate_mandate", arguments: { mandate: { payment_instruments: [{ network: "visa", ref_sha256: "4111111111111111" }] } } });
    expect(bad.isError).toBe(true);
    expect(text(bad).error).toBe("INVALID_INPUT");
  });

  it("reads the issuer for kya_verify and reports the price of paid tools without a key", async () => {
    const calls: string[] = [];
    const fetchImpl = (async (url: string) => {
      calls.push(url);
      if (url.includes("/allowed")) return new Response(JSON.stringify({}), { status: 402 });
      return new Response(JSON.stringify({ credential_id: CRED, status: "active", principal: { cnpj: "11222333000181", legal_name: "ACME LTDA" } }));
    }) as unknown as typeof fetch;
    const client = await connect(fetchImpl);
    expect(text(await client.callTool({ name: "kya_verify", arguments: { credential_id: CRED } })).principal.legal_name).toBe("ACME LTDA");
    expect(calls[0]).toBe(`https://kya.test/v1/agents/${CRED}`);
    const paid = await client.callTool({ name: "kya_check_action", arguments: { credential_id: CRED, action: "order" } });
    expect(paid.isError).toBe(true);
    expect(text(paid).error).toBe("PAYMENT_REQUIRED");
    const none = await client.callTool({ name: "kya_verify", arguments: {} });
    expect(text(none).error).toBe("INVALID_INPUT");
  });

  it("verifies a sub-agent's delegation chain and evaluates the action on every level", async () => {
    const credential = { credential_id: CRED, agent: { kind: "evm" as const, id: ROOT.address }, expires_at: new Date(Date.now() + 86400_000).toISOString(), mandate: validateMandate({ actions: ["order", "pay"], max_per_operation: { amount: 5000, currency: "BRL" }, delegation: { max_depth: 1, max_ttl_seconds: 3600 } }) };
    const { delegation, text: toSign } = await prepareDelegation({ credential, delegate: { kind: "evm", id: SUB.address }, mandate: { actions: ["order"], max_per_operation: { amount: 100, currency: "BRL" } }, ttlSeconds: 600 });
    const header = encodeDelegationHeader([{ ...delegation, signature: await ROOT.signMessage({ message: toSign }) }]);
    const client = await connect();
    const r = text(await client.callTool({ name: "kya_verify_delegation", arguments: { credential, chain: header, action: "order", amount: 500, currency: "BRL" } }));
    expect(r.ok).toBe(true);
    expect(r.delegate.id).toBe(SUB.address);
    expect(r.action.allowed).toBe(false); // the credential allows 500, the delegation only 100
    const forged = text(await client.callTool({ name: "kya_verify_delegation", arguments: { credential: { ...credential, agent: { kind: "evm", id: SUB.address } }, chain: header } }));
    expect(forged).toMatchObject({ ok: false, error: "KYA_DELEGATION_BAD_SIGNATURE" });
  });
});
