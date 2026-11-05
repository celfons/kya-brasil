/**
 * How much of the starter project the participant changed: files and lines, never their content. With git: a
 * baseline commit at init and `git diff --numstat` against it (through a temporary index, so the participant's own
 * index is untouched). Without git: a snapshot of each file's line hashes at init, compared as multisets.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { delimiter, isAbsolute, join, relative, sep } from "node:path";
import { STATE_DIR, paths } from "./workspace.js";

/** Never counted: dependencies, build output, the kit's state and test PKI, lock files, reports. */
const EXCLUDED_DIRS = new Set(["node_modules", "out", "dist", ".git", STATE_DIR, "pki"]);
const EXCLUDED_FILES = /^(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|kya-study-report-.*\.json)$/;
const GIT_EXCLUDES = [...[...EXCLUDED_DIRS].filter((d) => d !== ".git").map((d) => `:(exclude)${d}`), ":(exclude)package-lock.json", ":(exclude)pnpm-lock.yaml", ":(exclude)yarn.lock", ":(exclude)kya-study-report-*.json"];

export const GITIGNORE = ["node_modules/", "out/", "dist/", `${STATE_DIR}/`, "kya-study-report-*.json", ""].join("\n");

export interface ChangeStats {
  method: "git" | "snapshot";
  files_changed: number;
  lines_added: number;
  lines_removed: number;
}

const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

/**
 * Absolute path of the git executable, looked up only in the absolute directories of PATH (never the current
 * folder, which on Windows is searched first and here is the participant's workspace), or null.
 */
export function findGit(env: NodeJS.ProcessEnv = process.env): string | null {
  const names = process.platform === "win32" ? ["git.exe"] : ["git"]; // git.cmd would need a shell
  for (const dir of (env.PATH ?? env.Path ?? "").split(delimiter)) {
    if (!dir || !isAbsolute(dir)) continue;
    for (const name of names) {
      const f = join(dir, name);
      try {
        if (statSync(f).isFile()) return f;
      } catch { /* not here */ }
    }
  }
  return null;
}

function git(ws: string, args: string[], env?: Record<string, string>) {
  const bin = findGit();
  if (!bin) return { ok: false, out: "" };
  // Neutral identity and no signing: nothing of the participant's git config ends up in the baseline commit.
  const r = spawnSync(bin, ["-c", "user.name=kya-study", "-c", "user.email=kya-study@localhost", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", ...args], {
    cwd: ws, encoding: "utf8", env: { ...process.env, GIT_TERMINAL_PROMPT: "0", ...env }
  });
  return { ok: r.status === 0 && !r.error, out: r.stdout ?? "" };
}

export function gitAvailable(): boolean {
  if (process.env.KYA_STUDY_NO_GIT === "1") return false;
  const bin = findGit();
  if (!bin) return false;
  const r = spawnSync(bin, ["--version"], { encoding: "utf8" });
  return r.status === 0 && !r.error;
}

/** Creates the baseline at init: a commit when git is available (returns its hash), else a snapshot (returns null). */
export function makeBaseline(ws: string): { method: "git"; commit: string } | { method: "snapshot" } {
  if (gitAvailable()) {
    const isRepo = existsSync(join(ws, ".git"));
    if ((isRepo || git(ws, ["init", "-q"]).ok) && git(ws, ["add", "-A"]).ok && git(ws, ["commit", "-q", "--no-verify", "-m", "kya-study: baseline (starter project)"]).ok) {
      const head = git(ws, ["rev-parse", "HEAD"]);
      if (head.ok && /^[0-9a-f]{40,64}$/.test(head.out.trim())) return { method: "git", commit: head.out.trim() };
    }
  }
  writeFileSync(paths(ws).snapshot, JSON.stringify(snapshot(ws)));
  return { method: "snapshot" };
}

/** Line and file counts against the baseline. */
export function changeStats(ws: string, baseline: { method: "git"; commit: string } | { method: "snapshot" }): ChangeStats {
  if (baseline.method === "git" && gitAvailable()) {
    const index = join(ws, STATE_DIR, "diff-index");
    rmSync(index, { force: true });
    const env = { GIT_INDEX_FILE: index };
    const added = git(ws, ["add", "-A"], env);
    const diff = added.ok ? git(ws, ["diff", "--cached", "--numstat", baseline.commit, "--", ".", ...GIT_EXCLUDES], env) : { ok: false, out: "" };
    rmSync(index, { force: true });
    if (diff.ok) {
      let files = 0, plus = 0, minus = 0;
      for (const line of diff.out.split("\n")) {
        const m = /^(\d+|-)\t(\d+|-)\t/.exec(line);
        if (!m) continue;
        files++;
        plus += m[1] === "-" ? 0 : Number(m[1]);
        minus += m[2] === "-" ? 0 : Number(m[2]);
      }
      return { method: "git", files_changed: files, lines_added: plus, lines_removed: minus };
    }
  }
  const f = paths(ws).snapshot;
  const base: Snapshot = existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : {};
  return { method: "snapshot", ...compareSnapshots(base, snapshot(ws)) };
}

/** Relative path -> { file hash, line hash -> count }. Only hashes: no content is kept. */
export type Snapshot = Record<string, { sha256: string; lines: Record<string, number> }>;

export function snapshot(ws: string): Snapshot {
  const out: Snapshot = {};
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!EXCLUDED_DIRS.has(name)) walk(full);
      } else if (st.isFile() && !EXCLUDED_FILES.test(name) && st.size <= 2_000_000) {
        const buf = readFileSync(full);
        const lines: Record<string, number> = {};
        for (const l of buf.toString("utf8").split(/\r?\n/)) {
          const h = sha(l).slice(0, 16);
          lines[h] = (lines[h] ?? 0) + 1;
        }
        out[relative(ws, full).split(sep).join("/")] = { sha256: sha(buf), lines };
      }
    }
  };
  walk(ws);
  return out;
}

/** Files added, removed or modified, and lines added/removed as a multiset difference of line hashes. */
export function compareSnapshots(base: Snapshot, now: Snapshot): Omit<ChangeStats, "method"> {
  let files = 0, plus = 0, minus = 0;
  for (const name of new Set([...Object.keys(base), ...Object.keys(now)])) {
    const a = base[name], b = now[name];
    if (a && b && a.sha256 === b.sha256) continue;
    files++;
    const la = a?.lines ?? {}, lb = b?.lines ?? {};
    for (const h of new Set([...Object.keys(la), ...Object.keys(lb)])) {
      const d = (lb[h] ?? 0) - (la[h] ?? 0);
      if (d > 0) plus += d;
      else minus -= d;
    }
  }
  return { files_changed: files, lines_added: plus, lines_removed: minus };
}
