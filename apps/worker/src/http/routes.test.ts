import { describe, expect, it } from "vitest";
import { buildHttpApp } from "./routes";
import type { AppEnv } from "../env";
import { MAX_DESCRIPTION, REGISTRY_DESCRIPTION, TOOLS } from "../pricing";

/** Minimal env: KV and D1 as in-memory fakes, enough for the free routes that do not issue anything. */
function fakeEnv(): AppEnv {
  const kv = new Map<string, string>();
  const env = {
    X402_NETWORK: "eip155:84532",
    X402_FACILITATOR_URL: "https://x402.org/facilitator",
    FREE_TIER_DAILY_LIMIT: "2",
    PAY_TO: "0x0000000000000000000000000000000000000001",
    CACHE: {
      get: async (k: string, type?: string) => { const v = kv.get(k) ?? null; return v !== null && type === "json" ? JSON.parse(v) : v; },
      put: async (k: string, v: string) => { kv.set(k, v); }
    },
    DB: {
      prepare: () => ({
        bind() { return this; },
        first: async () => null,
        all: async () => ({ results: [] }),
        run: async () => ({})
      })
    }
  };
  return env as unknown as AppEnv;
}

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const call = (app: ReturnType<typeof buildHttpApp>, env: AppEnv, path: string, init?: RequestInit) => app.fetch(new Request(`https://kya.test${path}`, init), env, ctx);

describe("free routes", () => {
  const env = fakeEnv();
  const app = buildHttpApp(env);

  it("serves a landing page to browsers and JSON to everyone else at /", async () => {
    const html = await call(app, env, "/", { headers: { accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" } });
    expect(html.headers.get("content-type")).toMatch(/text\/html/);
    expect(await html.text()).toContain("kya_register");
    const json = await call(app, env, "/", { headers: { accept: "application/json" } });
    expect(json.headers.get("content-type")).toMatch(/application\/json/);
    const curl = await call(app, env, "/", { headers: { accept: "*/*" } });
    expect(curl.headers.get("content-type")).toMatch(/application\/json/);
  });

  it("lists the tools at / with prices", async () => {
    const j = (await (await call(app, env, "/")).json()) as { tools: Record<string, { price_usd: number }> };
    expect(j.tools.kya_register!.price_usd).toBe(0.2);
    expect(j.tools.kya_prove!.price_usd).toBe(0);
  });

  it("serves the mandate schema, openapi and llms.txt", async () => {
    const s = (await (await call(app, env, "/.well-known/kya-mandate.schema.json")).json()) as { $id: string; properties: Record<string, unknown> };
    expect(s.$id).toBe("https://kya.test/.well-known/kya-mandate.schema.json");
    expect(s.properties.actions).toBeDefined();
    const o = (await (await call(app, env, "/openapi.json")).json()) as { paths: Record<string, Record<string, unknown>> };
    expect(o.paths["/v1/agents"]!.post).toBeDefined();
    expect(o.paths["/v1/agents/{id}/allowed"]!.get).toBeDefined();
    expect(o.paths["/v1/acts/{act_id}"]).toBeUndefined();
    expect(o.paths["/v1/companies/{cnpj}/agents"]!.post).toBeDefined();
    expect(o.paths["/v1/companies/{cnpj}/webhook"]!.post).toBeDefined();
    const t = await (await call(app, env, "/llms.txt")).text();
    expect(t).toContain("kya_check_action");
  });

  it("unknown credential is 404 and counts against the free tier", async () => {
    expect((await call(app, env, "/v1/agents/nope")).status).toBe(404);
    expect((await call(app, env, "/v1/agents/nope")).status).toBe(404);
    const third = await call(app, env, "/v1/agents/nope");
    expect(third.status).toBe(429);
    expect(third.headers.get("retry-after")).toBeTruthy();
  });

  it("prove without a body is 400, never charged", async () => {
    const r = await call(app, env, "/v1/agents/nope/prove", { method: "POST", body: "not json" });
    expect(r.status).toBe(400);
    expect(((await r.json()) as { error: string }).error).toBe("INVALID_INPUT");
  });

  it("verify without a signing key says so", async () => {
    const r = await call(app, env, "/v1/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ attestation: { key_id: "x" } }) });
    const j = (await r.json()) as { valid: boolean; reason: string };
    expect(j.valid).toBe(false);
    expect(j.reason).toMatch(/no attestation key/);
  });

  it("internal channel refuses without the key", async () => {
    const r = await call(app, env, "/internal/v1/agents", { method: "POST", body: "{}" });
    expect(r.status).toBe(401);
  });

  it("unknown route is a JSON 404", async () => {
    const r = await call(app, env, "/v2/nothing");
    expect(r.status).toBe(404);
    expect(((await r.json()) as { error: string }).error).toBe("NOT_FOUND");
  });
});

describe("pricing", () => {
  it("keeps every description inside the facilitator limit", () => {
    for (const [name, t] of Object.entries(TOOLS)) expect(t.description.length, name).toBeLessThanOrEqual(MAX_DESCRIPTION);
    // The MCP Registry rejects a server.json description over 100 characters (422 on publish).
    expect(REGISTRY_DESCRIPTION.length).toBeLessThanOrEqual(100);
  });
});
