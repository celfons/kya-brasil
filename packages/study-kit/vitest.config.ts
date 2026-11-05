import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { defineConfig } from "vitest/config";

const require = createRequire(import.meta.url);
// tsx's ESM loader, for the child process that runs the participant's files (src/runner.ts is TypeScript here).
const tsx = pathToFileURL(require.resolve("tsx/esm")).href;

// In the workspace the libraries point at their TypeScript sources; both names resolve to the sources here, in the
// kit (aliases) and in the participant's child process (tsx with test/tsconfig.runner.json).
export default defineConfig({
  resolve: {
    alias: {
      "@kya-brasil/agent-tools": fileURLToPath(new URL("../agent-tools/src/index.ts", import.meta.url)),
      "@kya-brasil/core": fileURLToPath(new URL("../core/src/index.ts", import.meta.url))
    }
  },
  test: {
    testTimeout: 180_000,
    hookTimeout: 180_000,
    env: {
      KYA_STUDY_RUNNER_EXEC_ARGV: `--import ${tsx}`,
      TSX_TSCONFIG_PATH: fileURLToPath(new URL("./test/tsconfig.runner.json", import.meta.url))
    }
  }
});
