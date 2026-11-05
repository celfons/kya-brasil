// Regression tests for the QA findings on the first version of the kit (each test names the finding it covers).
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { main } from "./main.js";
import { makeCrl } from "./pki.js";
import { gradePolicy, referenceMandate } from "./policy.js";
import { scrub } from "./report.js";
import { kitSpec, paths, readAttempts, readConfig } from "./workspace.js";

const fixtures = fileURLToPath(new URL("../test/fixtures/", import.meta.url));
const pkgDir = fileURLToPath(new URL("../", import.meta.url));
const cli = fileURLToPath(new URL("./cli.ts", import.meta.url));
const roots: string[] = [];
afterAll(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});
afterEach(() => {
  delete process.env.KYA_STUDY_TIMEOUT_MS;
});

function io(cwd: string) {
  const out: string[] = [];
  return { out, text: () => out.join("\n"), io: { cwd, env: {}, out: (s: string) => out.push(s), err: (s: string) => out.push(s), ask: async () => null } };
}

async function workspace(): Promise<string> {
  const root = mkdtempSync(join(tmpdir(), "kya-study-qa-"));
  roots.push(root);
  const ws = join(root, "estudo");
  expect(await main(["init", ws, "--yes-consent"], io(root).io)).toBe(0);
  return ws;
}
const use = (ws: string, fixture: string, file: string) => cpSync(join(fixtures, fixture, file), join(ws, "src", file));
const last = (ws: string) => readAttempts(ws).at(-1)!;

/** The CLI as a participant runs it (tsx stands in for the build; the loader and tsconfig come from vitest.config.ts). */
const node = () => [process.execPath, ...(process.env.KYA_STUDY_RUNNER_EXEC_ARGV ?? "").split(" ").filter(Boolean), cli];
const hasPython = spawnSync("python3", ["--version"]).status === 0;

describe("QA 1 and 6: the terminal", () => {
  it.skipIf(!hasPython)("interactive init and finish exit by themselves in a real TTY", () => {
    const root = mkdtempSync(join(tmpdir(), "kya-study-tty-"));
    roots.push(root);
    const pty = (answers: string[], args: string[]) => {
      const r = spawnSync("python3", ["-I", join(pkgDir, "test", "pty-run.py"), root, "90", answers.join("|"), ...node(), ...args], { encoding: "utf8", env: process.env });
      return JSON.parse(r.stdout.trim().split("\n").at(-1)!) as { exited: boolean; code: number | null; sent: number; tail: string };
    };
    const init = pty(["aceito"], ["init", "estudo"]);
    expect(init, init.tail).toMatchObject({ exited: true, code: 0, sent: 1 });
    const ws = join(root, "estudo");
    expect(existsSync(join(ws, ".kya-study", "config.json"))).toBe(true);
    const finish = pty(["T3", "nada", "nada", "sim", "", "sim", "t3", "n", ""], ["finish", "--dir", ws]);
    expect(finish, finish.tail).toMatchObject({ exited: true, code: 0, sent: 9 });
    const answers = JSON.parse(readFileSync(paths(ws).answers, "utf8"));
    expect(answers).toMatchObject({ q1: "T3", ai_used: true, ai_tasks: ["t3"], library_changed: false });
  });

  it("finish with no input (EOF, e.g. < /dev/null) stops asking and records empty answers", async () => {
    const ws = await workspace();
    const r = spawnSync(node()[0]!, [...node().slice(1), "finish", "--dir", ws], { input: "", encoding: "utf8", timeout: 60_000, env: process.env });
    expect(r.signal, r.stdout + r.stderr).toBeNull();
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("a entrada terminou");
    const answers = JSON.parse(readFileSync(paths(ws).answers, "utf8"));
    expect(answers).toMatchObject({ q1: "", q4: "", ai_used: null, library_changed: null });
  });

  it("finish stops at EOF in the middle of the questions too (in-process)", async () => {
    const ws = await workspace();
    const replies = ["travou na T4", ""];
    const t = io(ws);
    expect(await main(["finish"], { ...t.io, ask: async () => (replies.length ? replies.shift()! : null) })).toBe(0);
    expect(JSON.parse(readFileSync(paths(ws).answers, "utf8")).q1).toBe("travou na T4");
  });
});

describe("QA 2: T3 does not depend on the CRL written at init", () => {
  it("passes with an expired pki/ac.crl (the kit issues a fresh CRL at each check)", async () => {
    const ws = await workspace();
    const ac = JSON.parse(readFileSync(paths(ws).ac, "utf8"));
    const day = 86_400_000;
    writeFileSync(join(ws, "pki", "ac.crl"), await makeCrl(ac, { thisUpdate: new Date(Date.now() - 30 * day), nextUpdate: new Date(Date.now() - 23 * day), revokeCompany: false }));
    use(ws, "solution", "verificar.mjs");
    const t = io(ws);
    expect(await main(["check", "t3"], t.io), t.text()).toBe(0);
  });
});

describe("QA 3: timeouts", () => {
  it("a verifier that never answers and an issuer stuck in a busy loop are logged as timeout", async () => {
    process.env.KYA_STUDY_TIMEOUT_MS = "2000";
    const ws = await workspace();
    use(ws, "hang", "verificar.mjs");
    use(ws, "busy", "emitir.mjs");
    const t = io(ws);
    expect(await main(["check", "t3"], t.io)).toBe(1);
    expect(last(ws)).toMatchObject({ task: "t3", pass: false, error_category: "timeout" });
    expect(t.text()).toContain("tempo esgotado");
    expect(await main(["check", "t1"], t.io)).toBe(1);
    expect(last(ws)).toMatchObject({ task: "t1", pass: false, error_category: "timeout" });
  });
});

describe("QA 4: T3 and T4 require the cryptography", () => {
  it("a verifier that only reads the JSON body fails every crypto case and the re-issued CRL", async () => {
    const ws = await workspace();
    use(ws, "blind", "verificar.mjs");
    const t = io(ws);
    expect(await main(["check", "t3"], t.io)).toBe(1);
    const t3 = last(ws);
    expect(t3.sub_cases?.filter((s) => !s.pass).map((s) => s.id).sort()).toEqual(["ac_nao_confiavel", "assinatura_adulterada", "chave_errada", "corpo_alterado", "mandato_adulterado"]);
    expect(t3.error_categories.sort()).toEqual(["icp_chain", "signature"]);
    expect(await main(["check", "t4"], t.io)).toBe(1);
    const t4 = last(ws);
    expect(t4.sub_cases?.map((s) => [s.id, s.pass])).toEqual([["antes_da_revogacao", true], ["lcr_reemitida", false], ["depois_da_revogacao", false]]);
    expect(readConfig(ws).t4_published_at).toBeUndefined();
  });
});

describe("QA 5, 9 and 11: categories and feedback", () => {
  it("a wrong .pfx password is icp_chain, with a hint about the .pfx and the password", async () => {
    const ws = await workspace();
    use(ws, "badpass", "emitir.mjs");
    const t = io(ws);
    expect(await main(["check", "t1"], t.io)).toBe(1);
    expect(last(ws).error_category).toBe("icp_chain");
    expect(t.text()).toContain("ctx.senha");
  });

  it("a verifier returning the wrong shape is a contract error", async () => {
    const ws = await workspace();
    use(ws, "contract", "verificar.mjs");
    const t = io(ws);
    expect(await main(["check", "t3"], t.io)).toBe(1);
    expect(last(ws).error_category).toBe("contract");
    expect(t.text()).toContain("{ aceito: boolean, motivo?: string }");
    expect(t.text()).not.toContain("lançou um erro");
  });

  it("a syntax error names the file and the line", async () => {
    const ws = await workspace();
    use(ws, "syntax", "verificar.mjs");
    const t = io(ws);
    expect(await main(["check", "t3"], t.io)).toBe(1);
    expect(last(ws).error_category).toBe("runtime");
    expect(t.text()).toMatch(/erro de sintaxe em src\/verificar\.mjs:3/);
  });
});

describe("QA 7, 8 and 15", () => {
  it("scrub keeps the user name as a word, removes every absolute path, keeps URLs", () => {
    expect(scrub("o root certificate da AC")).toBe("o root certificate da AC");
    expect(scrub("rodei em localhost:8787")).toBe("rodei em localhost:8787");
    expect(scrub("veja /etc/kya/x.conf e C:\\Users\\ana\\p e \\\\srv\\share e ~/proj")).toBe("veja <caminho> e <caminho> e <caminho> e <caminho>");
    expect(scrub("docs em https://github.com/celfons/kya-brasil#start-here, e/ou nada")).toBe("docs em https://github.com/celfons/kya-brasil#start-here, e/ou nada");
  });

  it("policy deviations carry no string the participant wrote", () => {
    const now = new Date();
    const r = gradePolicy({ mandate: { ...referenceMandate(now), actions: ["buy", "pagar_acme_industria"], currencies: ["BRL", "XYZ"], segredo_interno: 1, max_per_day: { amount: 1500, currency: "ACME" } }, issued_at: now.toISOString(), expires_at: new Date(now.getTime() + 30 * 86_400_000).toISOString() }, true);
    const text = JSON.stringify(r);
    for (const s of ["pagar_acme_industria", "XYZ", "segredo_interno", "ACME"]) expect(text).not.toContain(s);
    expect(r.deviations.map((d) => d.detail)).toContain("extra actions: 1");
  });

  it("the starter project references the kit as it was installed", () => {
    expect(kitSpec("file:/x/kit.tgz")).toBe("file:/x/kit.tgz");
    expect(kitSpec()).toBe(`file:${pkgDir.replace(/\/$/, "")}`);
  });
});

describe("QA 12 and 13: analyze.py", () => {
  it.skipIf(!hasPython)("skips structurally wrong reports with a reason and splits the results by AI use", () => {
    const dir = mkdtempSync(join(tmpdir(), "kya-study-an-"));
    roots.push(dir);
    const task = (s: number | null) => ({ attempts: 2, passes: s === null ? 0 : 1, pass_rate: 0.5, first_success_s: s, attempts_to_first_success: s === null ? null : 2, not_implemented_attempts: 0, errors: { runtime: 1 } });
    const report = (id: string, ai: boolean | null) => ({
      schema: "kya-study-report/1", participant_id: id, kit_version: "0.2.0", finished: true, total_s: 100,
      tasks: { t1: task(10), t2: task(20), t3: task(30), t4: task(null) },
      policy: { first_grade: "correct", first_deviations: [], last_grade: "correct", last_deviations: [] },
      revocation: { published_after_s: null, time_to_effect_s: null }, verification_latency_ms: { n: 1, median: 5, p25: 5, p75: 5 },
      changes: { method: "git", files_changed: 2, lines_added: 40, lines_removed: 10 }, library_change: { changed: false, where: "", requested: "" },
      ai_assistant: { used: ai, tasks: ai ? ["t3"] : [] }, answers: { q1: "a", q2: "b", q3: "c", q4: "d", q5: "" }
    });
    const write = (name: string, v: unknown) => writeFileSync(join(dir, `kya-study-report-${name}.json`), typeof v === "string" ? v : JSON.stringify(v));
    write("p-1", report("p-1", true));
    write("p-2", report("p-2", false));
    const noId = report("x", null) as Record<string, unknown>;
    delete noId.participant_id;
    write("noid", noId);
    write("list", { ...report("p-3", null), tasks: [] });
    write("str", { ...report("p-4", null), tasks: { t1: { ...task(1), first_success_s: "10" } } });
    write("broken", "{ nope");
    const r = spawnSync("python3", ["-I", join(pkgDir, "..", "..", "research", "study", "analyze.py"), dir], { encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    const summary = readFileSync(join(dir, "analysis", "summary.md"), "utf8");
    expect(summary).toContain("aggregate of 2 report(s)");
    expect(summary).toContain("kya-study-report-noid.json: participant_id missing");
    expect(summary).toContain("kya-study-report-list.json: tasks is not an object");
    expect(summary).toContain("kya-study-report-str.json: tasks.t1.first_success_s is not a number");
    expect(summary).toContain("kya-study-report-broken.json");
    expect(summary).toMatch(/\| used AI \| 1 \| 1\/1, 10\.0 \|/);
    expect(summary).toMatch(/\| no AI \| 1 \|/);
  });
});
