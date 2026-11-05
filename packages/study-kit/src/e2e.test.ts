// End to end: a simulated participant goes through init, check, finish and report in a temporary folder, with the
// reference solution from test/fixtures (never shipped). No network: fetch is stubbed to fail the test if called.
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "./main.js";
import type { StudyReport } from "./report.js";
import { readAttempts, readConfig } from "./workspace.js";

const fixtures = fileURLToPath(new URL("../test/fixtures/", import.meta.url));
const packages = fileURLToPath(new URL("../../", import.meta.url));
const roots: string[] = [];

function tempRoot() {
  const r = mkdtempSync(join(tmpdir(), "kya-study-"));
  roots.push(r);
  return r;
}

function io(cwd: string) {
  const out: string[] = [];
  return { out, io: { cwd, env: {}, out: (s: string) => out.push(s), err: (s: string) => out.push(s), ask: async () => "" } };
}

/** What `npm install` would give the participant: the libraries under node_modules (here, links to the workspace). */
function linkLibraries(ws: string) {
  mkdirSync(join(ws, "node_modules", "@kya-brasil"), { recursive: true });
  symlinkSync(join(packages, "core"), join(ws, "node_modules", "@kya-brasil", "core"), "dir");
  symlinkSync(join(packages, "agent-tools"), join(ws, "node_modules", "@kya-brasil", "agent-tools"), "dir");
}

beforeEach(() => {
  vi.stubGlobal("fetch", () => {
    throw new Error("the study kit must never use the network");
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.KYA_STUDY_NO_GIT;
});
afterAll(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

describe("kya-study, a participant who completes every task", () => {
  it("init, check, finish and report produce an anonymous report with the metrics", async () => {
    const root = tempRoot();
    const ws = join(root, "estudo");

    // Consent is required: anything but "aceito" creates nothing.
    const refused = io(root);
    expect(await main(["init", ws], { ...refused.io, ask: async () => "não" })).toBe(1);
    expect(existsSync(ws)).toBe(false);

    const init = io(root);
    expect(await main(["init", ws], { ...init.io, ask: async () => "aceito" })).toBe(0);
    expect(init.out.join("\n")).toContain("O QUE O KIT NÃO REGISTRA");
    for (const f of ["TASKS.md", "package.json", "src/emitir.mjs", "src/verificar.mjs", "pki/anchors.pem", "pki/ac.crl", "pki/empresa.pfx", "pki/representante.pfx", "pki/agente.json", "pki/LEIA-ME.txt", ".kya-study/config.json"]) {
      expect(existsSync(join(ws, f)), f).toBe(true);
    }
    const cfg = readConfig(ws);
    expect(cfg.participant_id).toMatch(/^p-[0-9a-f]{10}$/);
    expect(cfg.baseline.method).toBe("git");
    const starter = JSON.parse(readFileSync(join(ws, "package.json"), "utf8"));
    expect(starter.dependencies["@kya-brasil/core"]).toMatch(/^\^\d+\.\d+\.\d+$/);
    expect(starter.dependencies["@kya-brasil/agent-tools"]).toMatch(/^\^\d+\.\d+\.\d+$/);
    // Run from a checkout (not from node_modules): the kit is referenced by its folder, never a version that may not be on npm.
    expect(starter.devDependencies["@kya-brasil/study-kit"]).toMatch(/^file:\//);
    expect(readFileSync(join(ws, "TASKS.md"), "utf8")).toContain("R$ 500 por compra");
    linkLibraries(ws);

    // Starter files: every task fails as "not implemented", from a subfolder too (the workspace is found upwards).
    const first = io(join(ws, "src"));
    expect(await main(["check"], first.io)).toBe(1);
    expect(first.out.join("\n")).toContain("ainda não implementado");
    let log = readAttempts(ws);
    expect(log.map((a) => a.task)).toEqual(["t1", "t2", "t3", "t4"]);
    expect(log.every((a) => !a.pass && a.not_implemented && a.error_category === "runtime")).toBe(true);

    // The participant writes the reference solution.
    cpSync(join(fixtures, "solution", "emitir.mjs"), join(ws, "src", "emitir.mjs"));
    cpSync(join(fixtures, "solution", "verificar.mjs"), join(ws, "src", "verificar.mjs"));
    const done = io(ws);
    const code = await main(["check"], done.io);
    expect(done.out.join("\n")).toContain("política correta");
    expect(code, done.out.join("\n")).toBe(0);
    log = readAttempts(ws);
    expect(log).toHaveLength(8);
    expect(log.slice(4).every((a) => a.pass && a.error_category === null)).toBe(true);
    const t3 = log[6]!;
    expect(t3.sub_cases?.[0]?.id).toBe("compra_valida");
    expect(t3.sub_cases?.map((s) => s.id).sort()).toEqual(["ac_nao_confiavel", "acima_do_teto", "assinatura_adulterada", "chave_errada", "compra_valida", "corpo_alterado", "fornecedor_errado", "mandato_adulterado", "repeticao"]);
    expect(t3.sub_cases?.every((s) => s.pass)).toBe(true);
    expect(t3.verify_ms).toHaveLength(11); // three valid purchases and eight to refuse
    expect(t3.accept_ms).toHaveLength(3);
    expect(log[7]!.sub_cases?.map((s) => [s.id, s.pass])).toEqual([["antes_da_revogacao", true], ["lcr_reemitida", true], ["lcr_outra_revogacao", true], ["depois_da_revogacao", true]]);
    expect(log[7]!.accept_ms!.length).toBeGreaterThanOrEqual(4); // one CRL before, two to four re-issued, one or two purchases each
    expect(log[7]!.t4_published_at).toBeTruthy();

    // One task by name.
    expect(await main(["check", "t2"], io(ws).io)).toBe(0);

    const answersFile = join(root, "answers.json");
    writeFileSync(answersFile, JSON.stringify({
      q1: `T4, a LCR em ${homedir()}/projetos/kya demorou`, q2: "a validade; o root certificate da AC", q3: `nada; minha máquina ${hostname()} e meu e-mail fulana@example.com, log em /var/tmp/x.log`, q4: "sim", q5: "",
      ai_used: true, ai_tasks: "t1, T3 e nada mais",
      library_changed: false, library_where: "", library_request: "um exemplo de cache de LCR"
    }));
    expect(await main(["finish", "--answers", answersFile], io(ws).io)).toBe(0);

    const rep = io(ws);
    expect(await main(["report"], rep.io)).toBe(0);
    const file = join(ws, `kya-study-report-${cfg.participant_id}.json`);
    expect(rep.out.join("\n")).toContain(`kya-study-report-${cfg.participant_id}.json`);
    const raw = readFileSync(file, "utf8");
    const r = JSON.parse(raw) as StudyReport;

    expect(r.schema).toBe("kya-study-report/1");
    expect(r.participant_id).toBe(cfg.participant_id);
    expect(r.finished).toBe(true);
    expect(r.node_version).toBe(process.version);
    expect(["linux", "macos", "windows", "other"]).toContain(r.os_family);
    expect(r.library_versions["@kya-brasil/core"]).toMatch(/^\d+\.\d+\.\d+/);
    for (const t of ["t1", "t2", "t3", "t4"] as const) {
      expect(r.tasks[t].attempts).toBeGreaterThanOrEqual(2);
      expect(r.tasks[t].passes).toBeGreaterThanOrEqual(1);
      expect(r.tasks[t].first_success_s).toBeGreaterThanOrEqual(0);
      expect(r.tasks[t].attempts_to_first_success).toBe(2);
      expect(r.tasks[t].not_implemented_attempts).toBe(1);
      expect(r.tasks[t].errors.runtime).toBe(1);
    }
    expect(r.tasks.t3.sub_cases?.repeticao).toEqual({ attempts: 2, passes: 1, pass_rate: 0.5 });
    expect(r.errors_total.runtime).toBeGreaterThanOrEqual(4);
    expect(r.policy.first_grade).toBe("correct");
    expect(r.policy.last_grade).toBe("correct");
    expect(r.policy.first_deviations).toEqual([]);
    expect(r.revocation.published_after_s).toBeGreaterThanOrEqual(0);
    expect(r.revocation.time_to_effect_s).toBeGreaterThanOrEqual(0);
    expect(r.verification_latency_ms.n).toBe(3 + log[7]!.accept_ms!.length); // the accepted valid purchases only
    expect(r.verification_latency_ms.median).toBeGreaterThan(0);
    expect(r.changes.method).toBe("git");
    expect(r.changes.files_changed).toBe(2); // src/emitir.mjs and src/verificar.mjs; node_modules, .kya-study and pki are not counted
    expect(r.changes.lines_added).toBeGreaterThan(20);
    expect(r.library_change).toEqual({ changed: false, where: "", requested: "um exemplo de cache de LCR" });
    expect(r.answers.q1).toBe("T4, a LCR em <caminho> demorou");
    expect(r.answers.q2).toBe("a validade; o root certificate da AC");
    expect(r.answers.q3).toContain("log em <caminho>");
    expect(r.ai_assistant).toEqual({ used: true, tasks: ["t1", "t3"] });
    expect(r.library_integrity).toEqual({ checked: true, modified: false, versions_changed: false });

    // Nothing that identifies the person or the machine, and no code.
    expect(raw).not.toContain(homedir());
    const word = (w: string) => new RegExp(`(?<![\\p{L}\\p{N}_-])${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\p{L}\\p{N}_-])`, "iu");
    expect(raw).not.toMatch(word(hostname()));
    expect(raw).not.toContain(root);
    expect(raw).not.toContain("fulana@example.com");
    for (const code of ["createKyaAuth", "buildMandate", "import ", "export ", "privateKey", "BEGIN CERTIFICATE"]) expect(raw).not.toContain(code);
    for (const key of ["hostname", "username", "email", "path", "cwd"]) expect(Object.keys(r)).not.toContain(key);
  });
});

describe("kya-study, a participant who issues a too permissive mandate", () => {
  it("grades T2 as permissive, lists the deviating fields, and counts changes without git", async () => {
    process.env.KYA_STUDY_NO_GIT = "1";
    const root = tempRoot();
    const ws = join(root, "estudo");
    expect(await main(["init", ws, "--yes-consent"], io(root).io)).toBe(0);
    expect(readConfig(ws).baseline.method).toBe("snapshot");
    linkLibraries(ws);
    cpSync(join(fixtures, "permissive", "emitir.mjs"), join(ws, "src", "emitir.mjs"));

    const t1 = io(ws);
    expect(await main(["check", "t1"], t1.io)).toBe(0);
    const t2 = io(ws);
    expect(await main(["check", "politica"], t2.io)).toBe(1);
    expect(t2.out.join("\n")).toContain("política permissiva demais");

    const a = readAttempts(ws).at(-1)!;
    expect(a.task).toBe("t2");
    expect(a.pass).toBe(false);
    expect(a.error_category).toBe("mandate");
    expect(a.policy?.grade).toBe("permissive");
    const fields = a.policy!.deviations.filter((d) => d.direction === "permissive").map((d) => d.field).sort();
    expect(fields).toEqual(["counterparties", "delegation", "max_per_operation", "valid_until"]);

    // A naive verifier: no replay cache (T3 replay accepted) and a CRL kept past its nextUpdate (T4 refused, but
    // for staleness, not revocation).
    cpSync(join(fixtures, "naive", "verificar.mjs"), join(ws, "src", "verificar.mjs"));
    const naive = io(ws);
    expect(await main(["check", "t3"], naive.io)).toBe(1);
    expect(await main(["check", "t4"], naive.io)).toBe(1);
    const [t3, t4] = readAttempts(ws).slice(-2);
    expect(t3!.sub_cases?.filter((s) => !s.pass).map((s) => s.id)).toEqual(["repeticao"]);
    expect(t3!.error_category).toBe("replay");
    expect(t4!.sub_cases?.map((s) => s.pass)).toEqual([true, false, false, false]);
    expect(t4!.error_category).toBe("freshness");
    expect(naive.out.join("\n")).toContain("KYA_CERTIFICATE_STATUS_STALE");

    expect(await main(["report"], io(ws).io)).toBe(0);
    const r = JSON.parse(readFileSync(join(ws, `kya-study-report-${readConfig(ws).participant_id}.json`), "utf8")) as StudyReport;
    expect(r.finished).toBe(false);
    expect(r.policy.first_grade).toBe("permissive");
    expect(r.tasks.t1.passes).toBe(1);
    expect(r.tasks.t3).toMatchObject({ attempts: 1, passes: 0, first_success_s: null });
    expect(r.tasks.t3.errors.replay).toBe(1);
    expect(r.revocation.published_after_s).toBeNull(); // the naive verifier never got past the re-issued CRL
    expect(r.revocation.time_to_effect_s).toBeNull();
    expect(r.changes).toMatchObject({ method: "snapshot", files_changed: 2 });
    expect(r.changes.lines_added).toBeGreaterThan(10);
  });
});
