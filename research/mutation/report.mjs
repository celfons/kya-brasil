// Joins the batches Stryker wrote in data/ into results/results.json and results/RESULTS.md.
// Usage: node report.mjs
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA = join(HERE, "data");
const batches = readdirSync(DATA).filter((n) => /^mutation-[a-z]+\.json$/.test(n)).sort((a, b) => a.localeCompare(b));
if (batches.length !== 5) throw new Error(`expected the five batches in data/, found ${batches.join(", ") || "none"}`);

const files = {};
for (const name of batches) {
  const report = JSON.parse(readFileSync(join(DATA, name), "utf8"));
  for (const [path, file] of Object.entries(report.files)) {
    const count = { Killed: 0, Timeout: 0, Survived: 0, NoCoverage: 0, other: 0 };
    const survived = [];
    for (const m of file.mutants) {
      if (m.status in count) count[m.status]++;
      else if (m.status !== "Ignored") count.other++;
      if (m.status === "Survived" || m.status === "NoCoverage") survived.push({ line: m.location.start.line, mutator: m.mutatorName, replacement: m.replacement ?? null, status: m.status });
    }
    files[path] = { batch: name.slice(9, -5), ...count, survived };
  }
}
const total = (k) => Object.values(files).reduce((a, f) => a + f[k], 0);
const score = (f) => {
  const detected = f.Killed + f.Timeout;
  const all = detected + f.Survived + f.NoCoverage;
  return all ? Math.round((1000 * detected) / all) / 10 : null;
};
const sum = { Killed: total("Killed"), Timeout: total("Timeout"), Survived: total("Survived"), NoCoverage: total("NoCoverage"), other: total("other") };
const require_ = (p) => JSON.parse(readFileSync(p, "utf8"));
const results = {
  core_version: require_(join(HERE, "..", "..", "packages", "core", "package.json")).version,
  commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: HERE, encoding: "utf8", env: { PATH: "/usr/local/bin:/usr/bin:/bin" } }).trim(),
  stryker: require_(join(HERE, "node_modules", "@stryker-mutator", "core", "package.json")).version,
  mutants: sum.Killed + sum.Timeout + sum.Survived + sum.NoCoverage,
  ...sum,
  score: score(sum),
  files: Object.fromEntries(Object.entries(files).sort(([a], [b]) => a.localeCompare(b)).map(([p, f]) => [p, { ...f, score: score(f) }]))
};
mkdirSync(join(HERE, "results"), { recursive: true });
writeFileSync(join(HERE, "results", "results.json"), JSON.stringify(results, null, 2) + "\n");
const row = (name, f) => `| ${name} | ${f.Killed + f.Timeout + f.Survived + f.NoCoverage} | ${f.Killed} | ${f.Timeout} | ${f.Survived} | ${f.NoCoverage} | ${score(f)} |`;
writeFileSync(join(HERE, "results", "RESULTS.md"), `# Mutation testing of @kya-brasil/core

@kya-brasil/core ${results.core_version} (commit ${results.commit.slice(0, 12)}), Stryker ${results.stryker}, the library's own tests and vectors.
The score is the share of mutants a test detected (killed or timed out) among those that could be detected.

| File | Mutants | Killed | Timed out | Survived | No test reaches it | Score (%) |
|---|---:|---:|---:|---:|---:|---:|
${Object.entries(results.files).map(([p, f]) => row("`" + p + "`", f)).join("\n")}
${row("**All**", sum)}
`);
console.log(JSON.stringify({ mutants: results.mutants, ...sum, score: results.score }));
