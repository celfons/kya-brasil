/**
 * Adversarial vectors (H4), replay part: Alloy instances of docs/formal/adversarial.als over the threat model
 * (threats.als), written to docs/vectors/adversarial-v1.json. One request is signed with the vector's created and
 * expires and presented at each time in presented_at; createKyaAuth, with its default skew (300 s) and lifetime
 * (600 s) and memoryReplayCache when the vector says so, must answer as the model's verifier does.
 */
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { KYA_HEADERS, createKyaAuth, memoryReplayCache, signRequest } from "./auth";

interface ReplayVector {
  command: string;
  solution: number;
  source: "alloy" | "hand";
  kind: "replay";
  replay_cache: boolean;
  created: number;
  expires: number;
  presented_at: number[];
  expected: string[];
}

const FILE = new URL("../../../docs/vectors/adversarial-v1.json", import.meta.url);
const { vectors, epoch } = JSON.parse(readFileSync(FILE, "utf8")) as { vectors: ({ kind: string } & ReplayVector)[]; epoch: string };
const replays = vectors.filter((v): v is ReplayVector => v.kind === "replay");
const at = (s: number) => new Date(Date.parse(epoch) + s * 1000);

const EVM_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const EVM = privateKeyToAccount(EVM_PK).address;
const CRED = "6d0b1c2e-1111-4222-8333-444455556666";
const mandate = { actions: ["order"], max_per_operation: { amount: 5000, currency: "BRL" } };
const issuerFetch = (async () => new Response(JSON.stringify({ credential_id: CRED, status: "active", status_reason: null, agent: { kind: "evm", id: EVM }, principal: { cnpj: "11222333000181", legal_name: "ACME LTDA" }, credential: { mandate }, events: [] }))) as unknown as typeof fetch;
const url = "https://beta.com.br/orders";

describe("adversarial vectors (H4): signed-request window and replay", () => {
  afterEach(() => vi.useRealTimers());

  it("has vectors of every command", () => {
    const commands = new Set(replays.map((v) => v.command));
    for (const c of ["ReplayInsideWindow", "ReplayAfterExpiry", "CreatedInFuture", "WindowEdges", "LifetimeTooLong", "ExpiresBeforeCreated", "ReplayAcrossClockSkew", "ReplayThenExpired"]) expect(commands.has(c), c).toBe(true);
  });

  for (const v of replays) {
    it(`${v.command} #${v.solution} (${v.source}): ${v.expected.join(", ")}`, async () => {
      // The signed headers carry the vector's created and expires; the lifetime may exceed what the verifier accepts.
      const headers = await signRequest({ credentialId: CRED, key: { kind: "evm", privateKey: EVM_PK }, method: "POST", url, body: "a", now: at(v.created), ttlSeconds: v.expires - v.created });
      expect(Number(headers[KYA_HEADERS.created])).toBe(Math.floor(at(v.created).getTime() / 1000));
      expect(Number(headers[KYA_HEADERS.expires])).toBe(Math.floor(at(v.expires).getTime() / 1000));
      const auth = createKyaAuth({ baseUrl: "https://kya.test", fetch: issuerFetch, ...(v.replay_cache ? { replayCache: memoryReplayCache() } : {}) });
      vi.useFakeTimers({ toFake: ["Date"] });
      for (const [i, t] of v.presented_at.entries()) {
        vi.setSystemTime(at(t));
        const r = await auth.authenticate(new Request(url, { method: "POST", headers, body: "a" }));
        const got = r.ok ? "ok" : r.error;
        expect(got, `presentation ${i + 1} at +${t}s`).toBe(v.expected[i]);
      }
    });
  }
});
