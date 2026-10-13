#!/usr/bin/env node
/** Post-deploy smoke test. Exit 1 on any failure so the CD rolls back. */
const base = (process.argv[2] ?? "").replace(/\/$/, "");
if (!base) {
  console.error("usage: smoke.mjs <base url>");
  process.exit(2);
}
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
  const r = await fetch(`${base}/`);
  expect(r.status === 200, `status ${r.status}`);
  const j = await r.json();
  expect(j.tools?.kya_register?.price_usd === 0.5, "missing register tool");
});
await check("status: KYB bound through a service binding, signing key present", async () => {
  const j = await (await fetch(`${base}/status`)).json();
  expect(j.kyb_channel === "service-binding", `kyb_channel ${j.kyb_channel}`);
  expect(typeof j.attestation_key === "string" && j.attestation_key.length === 16, "no attestation key");
});
await check("register answers 402 with PAYMENT-REQUIRED (bazaar)", async () => {
  const r = await fetch(`${base}/v1/agents`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  expect(r.status === 402, `status ${r.status}`);
  const h = r.headers.get("PAYMENT-REQUIRED");
  expect(h, "no PAYMENT-REQUIRED header");
  const j = JSON.parse(Buffer.from(h, "base64").toString());
  expect(j.accepts?.[0]?.network && j.extensions?.bazaar, "incomplete 402");
});
await check("paid verification and verdict answer 402", async () => {
  for (const p of ["/v1/agents/00000000-0000-0000-0000-000000000000/verified", "/v1/agents/00000000-0000-0000-0000-000000000000/allowed?action=pay"]) {
    const r = await fetch(base + p);
    expect(r.status === 402, `${p} status ${r.status}`);
  }
});
await check("free verification of an unknown id is 404 (never charged)", async () => {
  const r = await fetch(`${base}/v1/agents/00000000-0000-0000-0000-000000000000`);
  expect(r.status === 404, `status ${r.status}`);
});
await check("mandate schema, keys, revocations, openapi, llms.txt", async () => {
  const s = await (await fetch(`${base}/.well-known/kya-mandate.schema.json`)).json();
  expect(s.properties?.actions, "schema without actions");
  const k = await (await fetch(`${base}/.well-known/kya.json`)).json();
  expect(Array.isArray(k.keys) && k.keys[0]?.jwk?.crv === "Ed25519", "no attestation key");
  const rv = await (await fetch(`${base}/v1/revocations`)).json();
  expect(Array.isArray(rv.revocations), "revocations not a list");
  const o = await (await fetch(`${base}/openapi.json`)).json();
  expect(o.paths?.["/v1/agents"]?.post, "openapi without register");
  const d = await (await fetch(`${base}/docs`)).text();
  expect(d.includes("swagger-ui"), "docs without Swagger UI");
  const t = await (await fetch(`${base}/llms.txt`)).text();
  expect(t.includes("kya_register"), "llms.txt without tools");
});
await check("MCP endpoint lists the tools", async () => {
  const r = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "smoke", version: "0" } } }) });
  expect(r.status === 200, `initialize status ${r.status}`);
  const sid = r.headers.get("mcp-session-id");
  expect(sid, "no mcp-session-id");
  await r.text();
  const l = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-session-id": sid }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) });
  const text = await l.text();
  expect(text.includes("kya_register") && text.includes("kya_check_action"), "tools/list without the KYA tools");
  const s = await (await fetch(`${base}/server.json`)).json();
  expect(s.remotes?.[0]?.url === `${base}/mcp`, "server.json remote mismatch");
});
await check("verifier rejects garbage", async () => {
  const v = await (await fetch(`${base}/v1/verify`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ attestation: { key_id: "x", signature: "x", sha256: "x", signed_at: "x" } }) })).json();
  expect(v.valid === false, "garbage verified as valid");
});
