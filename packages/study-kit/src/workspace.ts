/** The participant's workspace: where things live, the kit's state (.kya-study/) and the attempt log. */
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import type { ErrorCategory } from "./errors.js";

export const STATE_DIR = ".kya-study";
export const TASKS = ["t1", "t2", "t3", "t4"] as const;
export type TaskId = (typeof TASKS)[number];

export interface StudyConfig {
  schema: "kya-study-config/1";
  participant_id: string;
  kit_version: string;
  started_at: string;
  consent_at: string;
  /** How lines/files changed are counted: a baseline commit in the workspace's own git repository, or a snapshot of line hashes. */
  baseline: { method: "git"; commit: string } | { method: "snapshot" };
  /** T4: when the kit first published the revoked CRL (the first run whose pre-revocation request was accepted). */
  t4_published_at?: string;
  finished_at?: string;
}

export interface SubCase {
  id: string;
  expected: "accept" | "refuse";
  pass: boolean;
  category: ErrorCategory | null;
}

/** One line of .kya-study/log.jsonl: one attempt at one task. */
export interface Attempt {
  ts: string;
  task: TaskId;
  pass: boolean;
  /** First error category of the attempt (null when it passed). */
  error_category: ErrorCategory | null;
  /** Every distinct error category seen in the attempt (the sub-cases of T3/T4 can fail for different reasons). */
  error_categories: ErrorCategory[];
  /** Durations (ms) of each verification call of the attempt. */
  verify_ms: number[];
  /** Durations (ms) of the calls where the valid in-mandate purchase was accepted (the latency metric). */
  accept_ms?: number[];
  not_implemented?: boolean;
  sub_cases?: SubCase[];
  /** T2 only. */
  policy?: { grade: string; deviations: { field: string; direction: string; detail: string }[] };
  /** T4 only: when the revoked CRL was first published (wall clock). */
  t4_published_at?: string | null;
}

export const paths = (ws: string) => ({
  config: join(ws, STATE_DIR, "config.json"),
  log: join(ws, STATE_DIR, "log.jsonl"),
  answers: join(ws, STATE_DIR, "answers.json"),
  ac: join(ws, STATE_DIR, "pki-ac.json"),
  snapshot: join(ws, STATE_DIR, "baseline-snapshot.json"),
  pki: join(ws, "pki"),
  src: join(ws, "src")
});

/** The workspace containing `from` (it or a parent has .kya-study/config.json), or null. */
export function findWorkspace(from: string): string | null {
  let dir = resolve(from);
  for (;;) {
    if (existsSync(join(dir, STATE_DIR, "config.json"))) return dir;
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

export const readConfig = (ws: string): StudyConfig => JSON.parse(readFileSync(paths(ws).config, "utf8"));
export const writeConfig = (ws: string, c: StudyConfig) => writeFileSync(paths(ws).config, JSON.stringify(c, null, 2) + "\n");

export function appendAttempt(ws: string, a: Attempt) {
  appendFileSync(paths(ws).log, JSON.stringify(a) + "\n");
}

export function readAttempts(ws: string): Attempt[] {
  const f = paths(ws).log;
  if (!existsSync(f)) return [];
  return readFileSync(f, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .flatMap((l) => {
      try {
        return [JSON.parse(l) as Attempt];
      } catch {
        return [];
      }
    });
}

const here = dirname(fileURLToPath(import.meta.url));

/** This kit's own package.json (src/ or dist/ are one level below it). */
export function kitPackage(): { version: string; dependencies: Record<string, string> } {
  return JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
}

/** Version of an installed package, looked up in node_modules from `start` upwards (no require: the libraries are ESM-only). */
export function installedVersion(name: string, start: string): string | null {
  let dir = resolve(start);
  for (;;) {
    const f = join(dir, "node_modules", name, "package.json");
    if (existsSync(f)) {
      try {
        return String(JSON.parse(readFileSync(f, "utf8")).version);
      } catch {
        return null;
      }
    }
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

/** The project that installed the kit: the package.json just above the node_modules folder holding it, if any. */
function installer(): { dir: string; deps: Record<string, string> } | null {
  const parts = resolve(here, "..").split(sep);
  const i = parts.lastIndexOf("node_modules");
  if (i < 0) return null;
  const dir = parts.slice(0, i).join(sep) || sep;
  try {
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    return { dir, deps: { ...(pkg.devDependencies ?? {}), ...(pkg.dependencies ?? {}) } };
  } catch {
    return null;
  }
}

/** How the installing project got a package, with local paths made absolute (the participant's folder is elsewhere). */
function installedSpec(name: string): string | null {
  const inst = installer();
  const spec = inst?.deps[name];
  if (!inst || typeof spec !== "string" || spec.startsWith("workspace:")) return null;
  const local = spec.startsWith("file:") ? spec.slice(5) : /^(\.{1,2}[\\/]|[\\/])/.test(spec) ? spec : null;
  return local === null ? spec : `file:${isAbsolute(local) ? local : resolve(inst.dir, local)}`;
}

/**
 * The kit's own entry in the starter project's devDependencies, so that `npm install` there finds it the way it was
 * installed (registry, tarball or folder) instead of a registry version that may not exist: an explicit spec
 * (`init --kit <spec>` or KYA_STUDY_KIT_SPEC), else what the installing project declared, else the kit's folder
 * when it does not run from node_modules (a checkout), else the published version.
 */
export function kitSpec(explicit?: string): string {
  if (explicit) return explicit;
  const declared = installedSpec("@kya-brasil/study-kit");
  if (declared) return declared;
  const dir = resolve(here, "..");
  if (!dir.split(sep).includes("node_modules")) return `file:${dir}`;
  return `^${kitPackage().version}`;
}

/** Version range to put in the starter project for a library: as installed next to the kit, else the kit's own dependency, else the workspace's version. */
export function starterRange(name: string): string {
  const inst = installedSpec(name);
  if (inst) return inst;
  const declared = kitPackage().dependencies?.[name];
  if (declared && !declared.startsWith("workspace:")) return declared;
  const v = installedVersion(name, here);
  return v ? `^${v}` : "latest";
}

/** Library versions as the participant's project sees them (its node_modules), else the kit's. */
export function libraryVersions(ws: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of ["@kya-brasil/core", "@kya-brasil/agent-tools"]) out[name] = installedVersion(name, ws) ?? installedVersion(name, here) ?? "unknown";
  return out;
}
