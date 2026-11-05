// Regression tests for the QA findings on the first version of the kit (each test names the finding it covers).
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
    // "The CRL bytes changed, so it is revoked": the first re-issued CRL (plain or revoking another certificate) fails.
    const t4s = Object.fromEntries(t4.sub_cases!.map((s) => [s.id, s.pass]));
    expect(t4s).toMatchObject({ antes_da_revogacao: true, depois_da_revogacao: false });
    expect(t4s.lcr_reemitida && t4s.lcr_outra_revogacao).toBe(false);
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
    expect(scrub("at f (file:///home/ana/estudo/src/emitir.mjs:3:9) e file:///C:/Users/ana/x.mjs")).toBe("at f (<caminho>) e <caminho>");
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
    write("p-1-again", { ...report("p-1", true), finished: false });
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
    expect(summary).toContain("participant p-1: duplicate id");
    expect(summary).toMatch(/\| used AI \| 1 \| 1\/1, 10\.0 \|/);
    expect(summary).toMatch(/\| no AI \| 1 \|/);
  });
});

describe("QA 2 (second round): verifiers that game the order or the count of requests", () => {
  // From the second independent QA: each passed the first version of the randomized-free T3/T4.
  const cheats: [string, "t3" | "t4"][] = [["accept_first", "t3"], ["combo_nocrypto", "t3"], ["combo_nocrypto", "t4"], ["count2_revoked", "t4"], ["crl_length", "t4"], ["crl_count", "t4"], ["crl_clock", "t4"],
    // Third round: "the list grew by two" / "grew twice" (the revoking CRL is never longer than the ones before it).
    ["crl_entries_grew2", "t4"], ["crl_sticky_grew", "t4"]];
  it.each(cheats)("%s fails %s", async (cheat, task) => {
    const ws = await workspace();
    cpSync(join(fixtures, "cheats", `${cheat}.mjs`), join(ws, "src", "verificar.mjs"));
    const t = io(ws);
    expect(await main(["check", task], t.io), t.text()).toBe(1);
    expect(last(ws)).toMatchObject({ task, pass: false });
  });

  it("T4 requires the library's revocation code in motivo, not just a word", async () => {
    const ws = await workspace();
    const solution = readFileSync(join(fixtures, "solution", "verificar.mjs"), "utf8");
    writeFileSync(join(ws, "src", "verificar.mjs"), solution.replace("motivo: r.error }", 'motivo: r.error === "KYA_CERTIFICATE_REVOKED" ? "revoked" : r.error }'));
    expect(await main(["check", "t4"], io(ws).io)).toBe(1);
    expect(last(ws).sub_cases?.find((s) => s.id === "depois_da_revogacao")?.pass).toBe(false);
  });
});

describe("QA 3 (second round): finish keeps earlier answers unless the participant confirms", () => {
  const replies = (xs: (string | null)[]) => async () => (xs.length ? xs.shift()! : null);
  const full = ["T3", "nada", "nada", "sim", "", "nao", "n", ""];

  it("EOF or 'no' at the confirmation, and EOF in the middle, keep the first answers; 'yes' replaces them", async () => {
    const ws = await workspace();
    expect(await main(["finish"], { ...io(ws).io, ask: replies([...full]) })).toBe(0);
    const first = readFileSync(paths(ws).answers, "utf8");
    expect(await main(["finish"], { ...io(ws).io, ask: replies([]) })).toBe(0);
    expect(await main(["finish"], { ...io(ws).io, ask: replies(["n"]) })).toBe(0);
    expect(await main(["finish"], { ...io(ws).io, ask: replies(["s", "outra"]) })).toBe(0);
    expect(readFileSync(paths(ws).answers, "utf8")).toBe(first);
    expect(await main(["finish"], { ...io(ws).io, ask: replies(["s", "T4", ...full.slice(1)]) })).toBe(0);
    expect(JSON.parse(readFileSync(paths(ws).answers, "utf8")).q1).toBe("T4");
  });

  it("Ctrl-C saves nothing", async () => {
    const ws = await workspace();
    let stop = false;
    const ask = async () => {
      stop = true;
      return null;
    };
    expect(await main(["finish"], { ...io(ws).io, ask, interrupted: () => stop })).toBe(130);
    expect(existsSync(paths(ws).answers)).toBe(false);
  });

  it("'todas' means every task", async () => {
    const ws = await workspace();
    expect(await main(["finish"], { ...io(ws).io, ask: replies(["a", "b", "c", "d", "", "sim", "todas", "n", ""]) })).toBe(0);
    expect(JSON.parse(readFileSync(paths(ws).answers, "utf8")).ai_tasks).toEqual(["t1", "t2", "t3", "t4"]);
  });
});

describe("QA 4 (second round): a change to the installed library is measured", () => {
  it("records the library's digest at the first check and flags a later change", async () => {
    const ws = await workspace();
    for (const name of ["core", "agent-tools"]) {
      mkdirSync(join(ws, "node_modules", "@kya-brasil", name, "dist"), { recursive: true });
      writeFileSync(join(ws, "node_modules", "@kya-brasil", name, "package.json"), JSON.stringify({ name: `@kya-brasil/${name}`, version: "1.0.0" }));
      writeFileSync(join(ws, "node_modules", "@kya-brasil", name, "dist", "index.js"), "export {};\n");
    }
    await main(["check", "t2"], io(ws).io);
    expect(readConfig(ws).library_baseline?.sha256).toMatch(/^[0-9a-f]{64}$/);
    await main(["check", "t2"], io(ws).io);
    expect(readConfig(ws).library_modified_at).toBeUndefined();
    writeFileSync(join(ws, "node_modules", "@kya-brasil", "core", "dist", "index.js"), "export {};\n// patched\n");
    const t = io(ws);
    await main(["check", "t2"], t.io);
    expect(t.text()).toContain("os arquivos da biblioteca");
    expect(readConfig(ws).library_modified_at).toBeTruthy();
    expect(await main(["report"], io(ws).io)).toBe(0);
    const r = JSON.parse(readFileSync(join(ws, `kya-study-report-${readConfig(ws).participant_id}.json`), "utf8"));
    expect(r.library_integrity).toEqual({ checked: true, modified: true, versions_changed: false });
  });
});

describe("QA 5 (second round): analyze.py edge cases", () => {
  it.skipIf(!hasPython)("only broken files: exit 1 with the reasons; duplicate ids are reported; a missing folder is told apart", () => {
    const dir = mkdtempSync(join(tmpdir(), "kya-study-an2-"));
    roots.push(dir);
    const script = join(pkgDir, "..", "..", "research", "study", "analyze.py");
    writeFileSync(join(dir, "kya-study-report-a.json"), "{ nope");
    writeFileSync(join(dir, "kya-study-report-b.json"), JSON.stringify({ schema: "kya-study-report/1", tasks: {} }));
    const r = spawnSync("python3", ["-I", script, dir], { encoding: "utf8" });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("kya-study-report-a.json");
    expect(r.stderr).toContain("kya-study-report-b.json: participant_id missing");
    const missing = spawnSync("python3", ["-I", script, join(dir, "nao-existe")], { encoding: "utf8" });
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain("not a folder");
  });
});
