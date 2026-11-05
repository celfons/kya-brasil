import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// In the workspace the libraries point at their TypeScript sources; the participant's files (fixtures copied into a
// temporary workspace) import them by name, so both names resolve to the sources here.
export default defineConfig({
  resolve: {
    alias: {
      "@kya-brasil/agent-tools": fileURLToPath(new URL("../agent-tools/src/index.ts", import.meta.url)),
      "@kya-brasil/core": fileURLToPath(new URL("../core/src/index.ts", import.meta.url))
    }
  },
  test: { testTimeout: 120_000, hookTimeout: 120_000 }
});
