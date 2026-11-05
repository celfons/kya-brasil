/**
 * The anonymous report: metrics computed from the local log, the change counts and the open answers. No code, no
 * paths, no host name, no user name. This is the only file the participant sends.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, hostname, userInfo } from "node:os";
import { join } from "node:path";
import { ERROR_CATEGORIES, type ErrorCategory } from "./errors.js";
import { changeStats, type ChangeStats } from "./diffstats.js";
import { type Attempt, TASKS, type TaskId, libraryVersions, paths, readAttempts, readConfig } from "./workspace.js";

export interface Answers {
  q1: string;
  q2: string;
  q3: string;
  q4: string;
  q5: string;
  library_changed: boolean | null;
  library_where: string;
  library_request: string;
  answered_at: string;
}

export interface TaskMetrics {
  attempts: number;
  passes: number;
  pass_rate: number | null;
  /** Seconds from the start (consent) to the first passing attempt; null when it never passed. */
  first_success_s: number | null;
  /** Attempts until the first pass (inclusive). */
  attempts_to_first_success: number | null;
  errors: Record<ErrorCategory, number>;
  not_implemented_attempts: number;
  /** T3/T4: pass rate of each sub-case over the attempts. */
  sub_cases?: Record<string, { attempts: number; passes: number; pass_rate: number }>;
}

export interface StudyReport {
  schema: "kya-study-report/1";
  participant_id: string;
  kit_version: string;
  library_versions: Record<string, string>;
  node_version: string;
  os_family: string;
  /** Year and month of the session only. */
  study_month: string;
  finished: boolean;
  /** Seconds from the start to `finish` (or to the report when finish was not run). */
  total_s: number;
  tasks: Record<TaskId, TaskMetrics>;
  errors_total: Record<ErrorCategory, number>;
  policy: {
    /** Grade of the first verifiable mandate the participant issued (before any T2 feedback could change it). */
    first_grade: string | null;
    first_deviations: { field: string; direction: string; detail: string }[];
    /** Grade of the last T2 attempt. */
    last_grade: string | null;
    last_deviations: { field: string; direction: string; detail: string }[];
    grades_seen: Record<string, number>;
  };
  revocation: {
    /** Seconds from the start until the kit first published the revoked CRL (T4's pre-revocation request accepted). */
    published_after_s: number | null;
    /** Seconds from that publication to the first T4 pass: "tempo até a revogação valer". */
    time_to_effect_s: number | null;
  };
  verification_latency_ms: { n: number; median: number | null; p25: number | null; p75: number | null };
  changes: ChangeStats;
  library_change: { changed: boolean | null; where: string; requested: string };
  answers: { q1: string; q2: string; q3: string; q4: string; q5: string };
}

const emptyErrors = () => Object.fromEntries(ERROR_CATEGORIES.map((c) => [c, 0])) as Record<ErrorCategory, number>;

export function quantile(sorted: number[], q: number): number | null {
  if (!sorted.length) return null;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos), hi = Math.ceil(pos);
  return Math.round((sorted[lo]! + (sorted[hi]! - sorted[lo]!) * (pos - lo)) * 100) / 100;
}

/** Removes anything that could identify the machine or the person from free text: home directory, user name, host name. */
export function scrub(text: string): string {
  let s = String(text ?? "").slice(0, 4000);
  try {
    const h = homedir();
    if (h && h.length > 1) s = s.split(h).join("~");
  } catch { /* no home */ }
  const words: [string, string][] = [];
  try {
    words.push([userInfo().username, "<usuario>"]);
  } catch { /* no user */ }
  try {
    words.push([hostname(), "<maquina>"], [hostname().split(".")[0] ?? "", "<maquina>"]);
  } catch { /* no host */ }
  // User and host names as whole words (a short host name such as "vm" must not eat parts of other words).
  for (const [w, to] of words.filter(([w]) => w && w.trim().length >= 2).sort((a, b) => b[0].length - a[0].length)) {
    s = s.replace(new RegExp(`(?<![\\p{L}\\p{N}_-])${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}\\p{N}_-])`, "giu"), to);
  }
  // Absolute paths left (other users' homes, Windows profiles): keep only the last segment.
  s = s.replace(/(?:[A-Za-z]:\\|\/)(?:Users|home|usuarios|Usuários)[\\/][^\s\\/]+/gi, "~");
  // E-mail addresses.
  s = s.replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, "<email>");
  return s;
}

export function buildReport(ws: string, now = new Date()): StudyReport {
  const cfg = readConfig(ws);
  const attempts = readAttempts(ws);
  const start = Date.parse(cfg.started_at);
  const secs = (iso: string) => Math.round((Date.parse(iso) - start) / 100) / 10;

  const tasks = {} as Record<TaskId, TaskMetrics>;
  const errorsTotal = emptyErrors();
  for (const t of TASKS) {
    const list = attempts.filter((a) => a.task === t);
    const firstIdx = list.findIndex((a) => a.pass);
    const errors = emptyErrors();
    for (const a of list) for (const c of a.error_categories ?? []) if (c in errors) {
      errors[c]++;
      errorsTotal[c]++;
    }
    const m: TaskMetrics = {
      attempts: list.length,
      passes: list.filter((a) => a.pass).length,
      pass_rate: list.length ? Math.round((list.filter((a) => a.pass).length / list.length) * 1000) / 1000 : null,
      first_success_s: firstIdx >= 0 ? secs(list[firstIdx]!.ts) : null,
      attempts_to_first_success: firstIdx >= 0 ? firstIdx + 1 : null,
      errors,
      not_implemented_attempts: list.filter((a) => a.not_implemented).length
    };
    const subs = subCaseRates(list);
    if (subs) m.sub_cases = subs;
    tasks[t] = m;
  }

  const t2 = attempts.filter((a) => a.task === "t2" && a.policy);
  const firstVerifiable = t2.find((a) => a.policy!.grade !== "invalid");
  const last = t2[t2.length - 1];
  const grades: Record<string, number> = {};
  for (const a of t2) grades[a.policy!.grade] = (grades[a.policy!.grade] ?? 0) + 1;

  const published = cfg.t4_published_at ?? null;
  const t4pass = attempts.find((a) => a.task === "t4" && a.pass);
  const latencies = attempts.filter((a) => a.task === "t3" || a.task === "t4").flatMap((a) => a.verify_ms ?? []).sort((x, y) => x - y);

  const answers = readAnswers(ws);
  const end = cfg.finished_at ? Date.parse(cfg.finished_at) : now.getTime();
  return {
    schema: "kya-study-report/1",
    participant_id: cfg.participant_id,
    kit_version: cfg.kit_version,
    library_versions: libraryVersions(ws),
    node_version: process.version,
    os_family: process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : process.platform === "linux" ? "linux" : "other",
    study_month: cfg.started_at.slice(0, 7),
    finished: !!cfg.finished_at,
    total_s: Math.round((end - start) / 1000),
    tasks,
    errors_total: errorsTotal,
    policy: {
      first_grade: firstVerifiable?.policy?.grade ?? (t2.length ? "invalid" : null),
      first_deviations: firstVerifiable?.policy?.deviations ?? [],
      last_grade: last?.policy?.grade ?? null,
      last_deviations: last?.policy?.deviations ?? [],
      grades_seen: grades
    },
    revocation: {
      published_after_s: published ? secs(published) : null,
      time_to_effect_s: published && t4pass ? Math.max(0, Math.round((Date.parse(t4pass.ts) - Date.parse(published)) / 100) / 10) : null
    },
    verification_latency_ms: { n: latencies.length, median: quantile(latencies, 0.5), p25: quantile(latencies, 0.25), p75: quantile(latencies, 0.75) },
    changes: changeStats(ws, cfg.baseline),
    library_change: { changed: answers?.library_changed ?? null, where: scrub(answers?.library_where ?? ""), requested: scrub(answers?.library_request ?? "") },
    answers: { q1: scrub(answers?.q1 ?? ""), q2: scrub(answers?.q2 ?? ""), q3: scrub(answers?.q3 ?? ""), q4: scrub(answers?.q4 ?? ""), q5: scrub(answers?.q5 ?? "") }
  };
}

function subCaseRates(list: Attempt[]): TaskMetrics["sub_cases"] | undefined {
  const out: NonNullable<TaskMetrics["sub_cases"]> = {};
  for (const a of list) for (const s of a.sub_cases ?? []) {
    const r = (out[s.id] ??= { attempts: 0, passes: 0, pass_rate: 0 });
    r.attempts++;
    if (s.pass) r.passes++;
  }
  for (const r of Object.values(out)) r.pass_rate = Math.round((r.passes / r.attempts) * 1000) / 1000;
  return Object.keys(out).length ? out : undefined;
}

export function readAnswers(ws: string): Answers | null {
  const f = paths(ws).answers;
  return existsSync(f) ? (JSON.parse(readFileSync(f, "utf8")) as Answers) : null;
}

export function writeReport(ws: string, outDir = ws): { file: string; report: StudyReport } {
  const report = buildReport(ws);
  const file = join(outDir, `kya-study-report-${report.participant_id}.json`);
  writeFileSync(file, JSON.stringify(report, null, 2) + "\n");
  return { file, report };
}
