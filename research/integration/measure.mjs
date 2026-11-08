// Integration without participants (kya-paper, revista Section 8.1). No people are involved: the study kit's four
// tasks are run on the reference solution (packages/study-kit/test/fixtures/solution), the same files the kit's own
// end-to-end test uses, in a fresh workspace each time, with the network stubbed to fail. It records whether every
// task and sub-case passed in every run, the accept latency the kit measures, and what the solution takes: lines,
// library functions imported and called, packages. TEST ONLY PKI.
//
// The reference solution stays under test/fixtures and is not copied to examples/: the deferred H3 study asks
// participants to integrate from the documentation alone, and examples/ is part of that documentation.
//
// Run: pnpm --filter @kya-brasil/research-integration measure   (INTEGRATION_RUNS, default 20)
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir, cpus, platform } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { main } from "../../packages/study-kit/src/main.ts";
import { readAttempts } from "../../packages/study-kit/src/workspace.ts";

const RUNS = Number(process.env.INTEGRATION_RUNS ?? 20);
const packages = fileURLToPath(new URL("../../packages/", import.meta.url));
const solution = join(packages, "study-kit", "test", "fixtures", "solution");
const FILES = { "emitir.mjs": ["t1", "t2"], "verificar.mjs": ["t3", "t4"] };

process.env.KYA_STUDY_NO_GIT = "1";
// The child process that runs the solution resolves the libraries to the workspace's TypeScript sources, as the
// kit's own tests do (packages/study-kit/vitest.config.ts); a participant gets the published builds instead.
process.env.KYA_STUDY_RUNNER_EXEC_ARGV = `--import ${pathToFileURL(createRequire(import.meta.url).resolve("tsx/esm")).href}`;
process.env.TSX_TSCONFIG_PATH = join(packages, "study-kit", "test", "tsconfig.runner.json");
globalThis.fetch = () => {
  throw new Error("integration run must never use the network");
};

const io = (cwd) => ({ cwd, env: {}, out: (s) => process.env.INTEGRATION_DEBUG && process.stderr.write(`${s}\n`), err: (s) => process.stderr.write(`${s}\n`), ask: async () => "aceito" });
const version = (pkg) => JSON.parse(readFileSync(join(packages, pkg, "package.json"), "utf8")).version;

/** Lines that are not blank and not a whole-line comment; library functions imported, their call sites; packages. */
function codeCost(file) {
  const src = readFileSync(join(solution, file), "utf8");
  const lines = src.split("\n").filter((l) => l.trim() && !l.trim().startsWith("//"));
  const imports = [...src.matchAll(/import\s*\{([^}]*)\}\s*from\s*"(@kya-brasil\/[a-z-]+)"/g)];
  const functions = imports.flatMap((m) => m[1].split(",").map((s) => s.trim()).filter(Boolean));
  const body = lines.filter((l) => !l.trim().startsWith("import ")).join("\n");
  const calls = functions.reduce((n, f) => n + (body.match(new RegExp(`\\b${f}\\(`, "g")) ?? []).length, 0);
  return { tasks: FILES[file], lines: lines.length, packages: [...new Set(imports.map((m) => m[2]))].sort(), functions: functions.sort(), call_sites: calls };
}

const runs = [];
for (let i = 0; i < RUNS; i++) {
  const root = mkdtempSync(join(tmpdir(), "kya-integration-"));
  try {
    const ws = join(root, "estudo");
    if ((await main(["init", ws], io(root))) !== 0) throw new Error("init failed");
    mkdirSync(join(ws, "node_modules", "@kya-brasil"), { recursive: true });
    for (const p of ["core", "agent-tools"]) symlinkSync(join(packages, p), join(ws, "node_modules", "@kya-brasil", p), "dir");
    for (const f of Object.keys(FILES)) cpSync(join(solution, f), join(ws, "src", f));
    const code = await main(["check"], io(ws));
    const log = readAttempts(ws);
    runs.push({
      exit: code,
      tasks: Object.fromEntries(log.map((a) => [a.task, { pass: a.pass, sub_cases: a.sub_cases?.length ?? 0, sub_cases_passed: a.sub_cases?.filter((s) => s.pass).length ?? 0, policy: a.policy?.grade ?? null }])),
      accept_ms: log.flatMap((a) => a.accept_ms ?? [])
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const q = (xs, p) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.min(s.length - 1, Math.floor(p * s.length))] : null;
};
const accept = runs.flatMap((r) => r.accept_ms);
const files = Object.keys(FILES).map((f) => ({ file: f, ...codeCost(f) }));
const results = {
  generated_at: new Date().toISOString(),
  what: "study kit tasks T1 to T4 on the reference solution; no participants",
  solution: "packages/study-kit/test/fixtures/solution",
  versions: { core: version("core"), "agent-tools": version("agent-tools"), "study-kit": version("study-kit"), node: process.version },
  machine: { platform: platform(), cpus: cpus().length, model: cpus()[0]?.model ?? null },
  runs: RUNS,
  runs_all_passed: runs.filter((r) => r.exit === 0 && ["t1", "t2", "t3", "t4"].every((t) => r.tasks[t]?.pass)).length,
  tasks: Object.fromEntries(["t1", "t2", "t3", "t4"].map((t) => [t, {
    passed_runs: runs.filter((r) => r.tasks[t]?.pass).length,
    sub_cases_per_run: [...new Set(runs.map((r) => r.tasks[t]?.sub_cases ?? 0))].sort((a, b) => a - b),
    sub_cases_failed: runs.reduce((n, r) => n + ((r.tasks[t]?.sub_cases ?? 0) - (r.tasks[t]?.sub_cases_passed ?? 0)), 0),
    policy_grades: t === "t2" ? [...new Set(runs.map((r) => r.tasks[t]?.policy))] : undefined
  }])),
  accept_ms: { n: accept.length, median: q(accept, 0.5), p95: q(accept, 0.95), max: q(accept, 1) },
  code: {
    files,
    lines: files.reduce((n, f) => n + f.lines, 0),
    packages: [...new Set(files.flatMap((f) => f.packages))].sort(),
    functions: [...new Set(files.flatMap((f) => f.functions))].sort(),
    call_sites: files.reduce((n, f) => n + f.call_sites, 0)
  }
};
writeFileSync(new URL("results.json", import.meta.url), `${JSON.stringify(results, null, 2)}\n`);
console.log(JSON.stringify({ runs: results.runs, runs_all_passed: results.runs_all_passed, accept_ms: results.accept_ms, code: { lines: results.code.lines, functions: results.code.functions.length, call_sites: results.code.call_sites, packages: results.code.packages } }));
if (results.runs_all_passed !== RUNS) process.exit(1);
