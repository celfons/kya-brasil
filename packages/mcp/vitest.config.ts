import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: { "@kya-brasil/agent-tools": fileURLToPath(new URL("../agent-tools/src/index.ts", import.meta.url)) } }
});
