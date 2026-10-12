#!/usr/bin/env node
/**
 * Decide the MCP Registry version to publish.
 *   node scripts/registry-version.mjs <server.json> <registry search response>
 * Prints "unchanged" when the registry's latest entry already has the same remotes and
 * description; otherwise prints the next version (latest patch + 1, or server.json's version
 * when nothing is published yet).
 */
import { readFileSync } from "node:fs";

const local = JSON.parse(readFileSync(process.argv[2], "utf8"));
const search = JSON.parse(readFileSync(process.argv[3], "utf8"));
const entries = (search.servers ?? []).map((s) => s.server ?? s).filter((s) => s.name === local.name);

const cmp = (a, b) => {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  return 0;
};
const latest = entries.sort((a, b) => cmp(b.version, a.version))[0];
if (!latest) {
  console.log(local.version);
} else {
  const urls = (s) => JSON.stringify((s.remotes ?? []).map((r) => r.url).sort());
  if (urls(latest) === urls(local) && latest.description === local.description) {
    console.log("unchanged");
  } else {
    const [maj, min, pat] = latest.version.split(".").map(Number);
    const next = `${maj}.${min}.${(pat ?? 0) + 1}`;
    console.log(cmp(local.version, next) > 0 ? local.version : next);
  }
}
