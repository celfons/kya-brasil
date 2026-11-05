/**
 * Runs the participant's code in a child process (runner.ts) with a timeout per call: a promise that never settles
 * or a busy loop becomes a `timeout` attempt instead of hanging `check` or losing the attempt.
 */
import { type ChildProcess, fork } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface ErrorInfo {
  name: string;
  message: string;
  code: string | null;
  stack: string;
}

export type CallResult =
  | { kind: "ok"; value: Record<string, unknown> }
  | { kind: "error"; error: ErrorInfo; contract: string | null }
  | { kind: "timeout"; ms: number }
  | { kind: "crash"; detail: string };

const here = dirname(fileURLToPath(import.meta.url));

/** Per-call timeout in ms (KYA_STUDY_TIMEOUT_MS, default 10 s). Loading the participant's modules gets three times it. */
export const callTimeoutMs = () => {
  const v = Number(process.env.KYA_STUDY_TIMEOUT_MS);
  return Number.isFinite(v) && v > 0 ? v : 10_000;
};

export class Sandbox {
  private child: ChildProcess | null = null;
  private seq = 0;
  private pending = new Map<number, (r: CallResult) => void>();
  private exitDetail = "";
  private timedOut = 0;

  constructor(private ws: string) {}

  private start(): Promise<void> {
    const built = join(here, "runner.js");
    // In the published package dist/runner.js runs on plain Node; in the monorepo tests run src/runner.ts through the
    // loader given in KYA_STUDY_RUNNER_EXEC_ARGV (tsx).
    const script = existsSync(built) ? built : join(here, "runner.ts");
    const execArgv = (process.env.KYA_STUDY_RUNNER_EXEC_ARGV ?? "").split(" ").filter(Boolean);
    const child = fork(script, [this.ws], { cwd: this.ws, execArgv, serialization: "advanced", stdio: ["ignore", "inherit", "inherit", "ipc"] });
    this.child = child;
    return new Promise((resolve) => {
      const ready = (m: { id?: number; ready?: boolean }) => {
        if (m && m.id === 0 && m.ready) {
          child.off("message", ready);
          child.on("message", (r: { id: number }) => {
            const done = this.pending.get(r.id);
            if (!done) return;
            this.pending.delete(r.id);
            const msg = r as unknown as { ok: boolean; contract?: string | null; error?: ErrorInfo } & Record<string, unknown>;
            done(msg.ok ? { kind: "ok", value: msg } : { kind: "error", error: msg.error!, contract: msg.contract ?? null });
          });
          resolve();
        }
      };
      child.on("message", ready);
      child.on("exit", (code, signal) => {
        this.exitDetail = `o processo do seu código terminou (${signal ?? `código ${code}`})`;
        for (const [, done] of this.pending) done({ kind: "crash", detail: this.exitDetail });
        this.pending.clear();
        this.child = null;
        resolve();
      });
    });
  }

  async call(op: string, payload: Record<string, unknown>, timeoutMs = callTimeoutMs()): Promise<CallResult> {
    if (!this.child) {
      // After a timeout the verifier's state is gone: the remaining calls of the attempt time out too.
      if (this.timedOut) return { kind: "timeout", ms: this.timedOut };
      if (this.exitDetail) return { kind: "crash", detail: this.exitDetail };
      await this.start();
      if (!this.child) return { kind: "crash", detail: this.exitDetail || "não foi possível iniciar o processo" };
    }
    const id = ++this.seq;
    return new Promise<CallResult>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.timedOut = timeoutMs;
        this.kill();
        resolve({ kind: "timeout", ms: timeoutMs });
      }, timeoutMs);
      this.pending.set(id, (r) => {
        clearTimeout(timer);
        resolve(r);
      });
      this.child!.send({ id, op, ...payload });
    });
  }

  kill() {
    const c = this.child;
    this.child = null;
    if (c && c.exitCode === null) c.kill("SIGKILL");
  }
}
