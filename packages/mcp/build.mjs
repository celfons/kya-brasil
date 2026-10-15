// One self-contained ESM file: the workspace packages (@kya-brasil/core, @kya-brasil/agent-tools) point at their
// TypeScript sources, so the server is bundled instead of resolved at run time. `npx @kya-brasil/mcp` and a
// Docker image built from this repository run the same file.
import { build } from "esbuild";

await build({
  entryPoints: ["src/index.ts"],
  tsconfig: "tsconfig.json",
  outfile: "dist/index.js",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  // PKCS#11 (A3 tokens) is an optional native module of agent-tools that this server never loads.
  external: ["pkcs11js"],
  // Some bundled dependencies are CommonJS and call require().
  banner: { js: "import { createRequire as __kyaCreateRequire } from 'node:module'; const require = __kyaCreateRequire(import.meta.url);" },
  logLevel: "info"
});
