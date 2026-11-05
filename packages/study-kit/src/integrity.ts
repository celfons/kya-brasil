/**
 * Whether the participant changed the installed library (H3: "without changing the library"). The kit makes no
 * network calls, so it cannot compare with the published packages: the first `check` that finds
 * node_modules/@kya-brasil/{core,agent-tools} records a digest of their files, and every later `check` compares
 * with it. Only the digest and a yes/no reach the report, never a file name or content. A change made before the
 * first `check` is not seen; the questionnaire still asks.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { readConfig, writeConfig } from "./workspace.js";

export const WATCHED = ["core", "agent-tools"] as const;

export interface LibraryDigest {
  versions: Record<string, string>;
  sha256: string;
}

function files(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir).sort()) {
    if (name === "node_modules") continue;
    const f = join(dir, name);
    const st = statSync(f);
    if (st.isDirectory()) files(f, out);
    else if (st.isFile()) out.push(f);
  }
  return out;
}

/** Digest of the installed @kya-brasil libraries in the workspace, or null when they are not installed there. */
export function libraryDigest(ws: string): LibraryDigest | null {
  const h = createHash("sha256");
  const versions: Record<string, string> = {};
  for (const name of WATCHED) {
    const dir = join(ws, "node_modules", "@kya-brasil", name);
    if (!existsSync(join(dir, "package.json"))) return null;
    versions[`@kya-brasil/${name}`] = String(JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version);
    for (const f of files(dir)) {
      h.update(`${name}/${relative(dir, f).split(sep).join("/")}\0`);
      h.update(readFileSync(f));
      h.update("\0");
    }
  }
  return { versions, sha256: h.digest("hex") };
}

/**
 * Called at each `check`: records the baseline the first time, then notes when the files differ from it (same
 * versions) or when other versions were installed. Returns a line for the terminal when something changed.
 */
export function trackLibrary(ws: string, now = new Date()): string | null {
  const d = libraryDigest(ws);
  if (!d) return null;
  const cfg = readConfig(ws);
  if (!cfg.library_baseline) {
    cfg.library_baseline = { ...d, at: now.toISOString() };
    writeConfig(ws, cfg);
    return null;
  }
  if (d.sha256 === cfg.library_baseline.sha256) return null;
  const sameVersions = JSON.stringify(d.versions) === JSON.stringify(cfg.library_baseline.versions);
  if (sameVersions) cfg.library_modified_at ??= now.toISOString();
  else cfg.library_versions_changed_at ??= now.toISOString();
  writeConfig(ws, cfg);
  return sameVersions
    ? "aviso: os arquivos da biblioteca (node_modules/@kya-brasil) mudaram desde o primeiro check; isso fica registrado no relatório (só sim/não)."
    : "aviso: outra versão da biblioteca foi instalada desde o primeiro check; isso fica registrado no relatório.";
}
