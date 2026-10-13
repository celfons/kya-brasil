#!/usr/bin/env node
/**
 * Decide the MCP Registry version to publish.
 *   node scripts/registry-version.mjs <server.json> <registry search response>
 * Prints "unchanged" when the registry's latest entry already has the same remotes and
 * description; otherwise prints the next version (latest patch + 1, or server.json's version
 * when nothing is published yet).
 */
import { readFileSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

/** Only relative paths without "..", resolved inside the working directory (the CD passes server.json latest.json). */
function insideCwd(arg) {
  const base = process.cwd();
  if (typeof arg !== "string" || !arg || isAbsolute(arg) || arg.split(/[\\/]/).includes("..")) throw new Error(`refused path: ${arg}`);
  const target = resolve(base, arg);
  const rel = relative(base, target);
  if (rel.startsWith("..") || isAbsolute(rel)) throw new Error(`refused path: ${arg}`);
  return target;
}

const local = JSON.parse(readFileSync(insideCwd(process.argv[2]), "utf8"));
const search = JSON.parse(readFileSync(insideCwd(process.argv[3]), "utf8"));
const entries = (search.servers ?? []).map((s) => s.server ?? s).filter((s) => s.name === local.name);

/** Versions are parsed into three integers; only values rebuilt from those integers are ever printed. */
function parseVersion(v) {
  const m = /^(\d{1,6})\.(\d{1,6})\.(\d{1,6})$/.exec(typeof v === "string" ? v : "");
  if (!m) throw new Error("version is not MAJOR.MINOR.PATCH");
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}
const format = ([maj, min, pat]) => `${maj}.${min}.${pat}`;
const cmp = (a, b) => {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};

const localVersion = parseVersion(local.version);
const latest = entries.map((e) => ({ ...e, parsed: parseVersion(e.version) })).sort((a, b) => cmp(b.parsed, a.parsed))[0];
if (!latest) {
  process.stdout.write(format(localVersion) + "\n");
} else {
  const urls = (s) => JSON.stringify((s.remotes ?? []).map((r) => r.url).sort((a, b) => a.localeCompare(b)));
  if (urls(latest) === urls(local) && latest.description === local.description) {
    process.stdout.write("unchanged\n");
  } else {
    const next = [latest.parsed[0], latest.parsed[1], latest.parsed[2] + 1];
    process.stdout.write(format(cmp(localVersion, next) > 0 ? localVersion : next) + "\n");
  }
}
