// Starts the bundled server over stdio, as an MCP client (or Glama's checks) would, and lists its tools.
import { spawn } from "node:child_process";

const child = spawn(process.execPath, [new URL("./dist/index.js", import.meta.url).pathname], { stdio: ["pipe", "pipe", "inherit"], env: { ...process.env, KYA_PRIVATE_KEY: "" } });
const send = (m) => child.stdin.write(JSON.stringify(m) + "\n");
const timer = setTimeout(() => { console.error("no answer from the server within 15 s"); child.kill(); process.exit(1); }, 15_000);
let buf = "";
child.stdout.on("data", (d) => {
  buf += d;
  for (let i; (i = buf.indexOf("\n")) >= 0; ) {
    const msg = JSON.parse(buf.slice(0, i));
    buf = buf.slice(i + 1);
    if (msg.id === 1) {
      send({ jsonrpc: "2.0", method: "notifications/initialized" });
      send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    }
    if (msg.id === 2) {
      const names = msg.result.tools.map((t) => t.name);
      console.log(`${msg.result.tools.length} tools: ${names.join(", ")}`);
      clearTimeout(timer);
      child.kill();
      process.exit(names.includes("kya_verify") && names.includes("kya_check_mandate") ? 0 : 1);
    }
  }
});
send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "smoke", version: "0" } } });
