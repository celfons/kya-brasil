#!/usr/bin/env node
/**
 * Post-deploy smoke test. Exit 1 on any failure so the CD rolls back.
 *   node scripts/smoke.mjs <base url>
 * The base URL must be https on a *.workers.dev host (what the CD deploys to), or http(s) on localhost for a
 * local run. A self-hosted issuer on its own domain adds it to SMOKE_ALLOWED_HOSTS (comma-separated).
 * Every request is built with new URL(path, base), so only paths of that origin are ever fetched.
 */
const LOCAL_HOSTS = ["localhost", "127.0.0.1"];
function baseFrom(arg) {
  let u;
  try {
    u = new URL(arg ?? "");
  } catch {
    return null;
  }
  const extra = (process.env.SMOKE_ALLOWED_HOSTS ?? "").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);
  const local = LOCAL_HOSTS.includes(u.hostname);
  const protocolOk = u.protocol === "https:" || (u.protocol === "http:" && local);
  const hostOk = local || u.hostname.endsWith(".workers.dev") || extra.includes(u.hostname);
  if (!protocolOk || !hostOk || u.username || u.password) return null;
  return new URL(u.origin);
}
const base = baseFrom(process.argv[2]);
if (!base) {
  console.error("usage: smoke.mjs <base url>  (https://<name>.workers.dev, http://localhost:<port>, or a host listed in SMOKE_ALLOWED_HOSTS)");
  process.exit(2);
}
const at = (path) => new URL(path, base).toString();
// A freshly created Worker takes a few seconds to reach every edge location; retry before failing.
const check = async (name, fn, attempts = 4) => {
  for (let i = 1; ; i++) {
    try {
      await fn();
      console.log("ok  ", name + (i > 1 ? ` (attempt ${i})` : ""));
      return;
    } catch (e) {
      if (i >= attempts) {
        console.error("FAIL", name, e.message);
        process.exitCode = 1;
        return;
      }
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
};
const expect = (cond, msg) => { if (!cond) throw new Error(msg); };

await check("GET / lists tools", async () => {
  const r = await fetch(at("/"));
  expect(r.status === 200, `status ${r.status}`);
  const j = await r.json();
  expect(j.tools?.kya_register?.price_usd === 0.5, "missing register tool");
});
await check("status: a registration source configured, signing key present", async () => {
  const j = await (await fetch(at("/status"))).json();
  // D-17: KYB is optional. With it, the channel must be the service binding; without it, the public sources.
  const ok = (j.registration_source === "kyb" && j.kyb_channel === "service-binding") || (j.registration_source === "public" && j.kyb_channel === "missing");
  expect(ok, `registration_source ${j.registration_source}, kyb_channel ${j.kyb_channel}`);
  expect(typeof j.attestation_key === "string" && j.attestation_key.length === 16, "no attestation key");
});
await check("register answers 402 with PAYMENT-REQUIRED (bazaar)", async () => {
  const r = await fetch(at("/v1/agents"), { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  expect(r.status === 402, `status ${r.status}`);
  const h = r.headers.get("PAYMENT-REQUIRED");
  expect(h, "no PAYMENT-REQUIRED header");
  const j = JSON.parse(Buffer.from(h, "base64").toString());
  expect(j.accepts?.[0]?.network && j.extensions?.bazaar, "incomplete 402");
});
await check("paid verification and verdict answer 402", async () => {
  for (const p of ["/v1/agents/00000000-0000-0000-0000-000000000000/verified", "/v1/agents/00000000-0000-0000-0000-000000000000/allowed?action=pay"]) {
    const r = await fetch(at(p));
    expect(r.status === 402, `${p} status ${r.status}`);
  }
});
await check("act registration answers 402; unknown act is 404", async () => {
  const r = await fetch(at("/v1/agents/00000000-0000-0000-0000-000000000000/acts"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "pay" }) });
  expect(r.status === 402, `status ${r.status}`);
  const a = await fetch(at("/v1/acts/00000000-0000-0000-0000-000000000000"));
  expect(a.status === 404, `act status ${a.status}`);
});
await check("free verification of an unknown id is 404 (never charged)", async () => {
  const r = await fetch(at("/v1/agents/00000000-0000-0000-0000-000000000000"));
  expect(r.status === 404, `status ${r.status}`);
});
await check("mandate schema, keys, revocations, openapi, llms.txt", async () => {
  const s = await (await fetch(at("/.well-known/kya-mandate.schema.json"))).json();
  expect(s.properties?.actions, "schema without actions");
  const k = await (await fetch(at("/.well-known/kya.json"))).json();
  expect(Array.isArray(k.keys) && k.keys[0]?.jwk?.crv === "Ed25519", "no attestation key");
  const rv = await (await fetch(at("/v1/revocations"))).json();
  expect(Array.isArray(rv.revocations), "revocations not a list");
  const o = await (await fetch(at("/openapi.json"))).json();
  expect(o.paths?.["/v1/agents"]?.post, "openapi without register");
  const d = await (await fetch(at("/docs"))).text();
  expect(d.includes("swagger-ui"), "docs without Swagger UI");
  const t = await (await fetch(at("/llms.txt"))).text();
  expect(t.includes("kya_register"), "llms.txt without tools");
});
await check("MCP endpoint lists the tools", async () => {
  const r = await fetch(at("/mcp"), { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "smoke", version: "0" } } }) });
  expect(r.status === 200, `initialize status ${r.status}`);
  const sid = r.headers.get("mcp-session-id");
  expect(sid, "no mcp-session-id");
  await r.text();
  const l = await fetch(at("/mcp"), { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-session-id": sid }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) });
  const text = await l.text();
  expect(text.includes("kya_register") && text.includes("kya_check_action"), "tools/list without the KYA tools");
  const s = await (await fetch(at("/server.json"))).json();
  expect(s.remotes?.[0]?.url === at("/mcp"), "server.json remote mismatch");
});
await check("verifier rejects garbage", async () => {
  const v = await (await fetch(at("/v1/verify"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ attestation: { key_id: "x", signature: "x", sha256: "x", signed_at: "x" } }) })).json();
  expect(v.valid === false, "garbage verified as valid");
});
