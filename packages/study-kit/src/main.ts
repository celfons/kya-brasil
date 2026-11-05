/**
 * kya-study: init | check [task] | finish | report. Every command works on the local workspace only.
 * Hidden flags for automated tests: init --yes-consent (or KYA_STUDY_CONSENT=aceito), finish --answers <file.json>.
 */
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve, sep } from "node:path";
import { createInterface } from "node:readline/promises";
import { GITIGNORE, makeBaseline } from "./diffstats.js";
import { COMPANY_CNPJ, CRL_URL, REPRESENTATIVE_CPF, TEST_PASSWORD, WARNING, makeTestPki } from "./pki.js";
import { type Answers, writeReport } from "./report.js";
import { RUNNERS, loadMaterial } from "./tasks.js";
import { CATEGORY_PT, CONSENT, CONSENT_PROMPT, HINT_PT, LIBRARY_QUESTIONS, QUESTIONS, STARTER_EMITIR, STARTER_VERIFICAR, tasksMd } from "./texts.js";
import { STATE_DIR, TASKS, type StudyConfig, type TaskId, appendAttempt, findWorkspace, kitPackage, paths, readConfig, starterRange, writeConfig } from "./workspace.js";

export interface Io {
  cwd: string;
  env: Record<string, string | undefined>;
  out: (s: string) => void;
  err: (s: string) => void;
  /** Asks one question in the terminal and returns the answer (without the newline). */
  ask: (q: string) => Promise<string>;
}

function defaultIo(): Io {
  let rl: ReturnType<typeof createInterface> | null = null;
  let lines: string[] | null = null;
  return {
    cwd: process.cwd(),
    env: process.env,
    out: (s) => process.stdout.write(s + "\n"),
    err: (s) => process.stderr.write(s + "\n"),
    ask: async (q) => {
      if (process.stdin.isTTY) {
        rl ??= createInterface({ input: process.stdin, output: process.stdout });
        return rl.question(q);
      }
      // Piped input: read it all once, one answer per line.
      if (!lines) {
        const chunks: Buffer[] = [];
        for await (const c of process.stdin) chunks.push(c as Buffer);
        lines = Buffer.concat(chunks).toString("utf8").split(/\r?\n/);
      }
      process.stdout.write(q + "\n");
      return lines.shift() ?? "";
    }
  };
}

const HELP = `kya-study: kit do estudo de caso KYA Brasil (tudo local, sem rede)

  kya-study init [pasta]     termo de consentimento e criação da pasta de trabalho
  kya-study check [tarefa]   avalia as tarefas (t1, t2, t3, t4; sem argumento: todas)
  kya-study finish           perguntas abertas do fim
  kya-study report           gera o relatório anônimo para enviar ao pesquisador

Opções: --dir <pasta>  pasta de trabalho (padrão: a atual ou uma acima dela)`;

export async function main(argv: string[], ioIn: Partial<Io> = {}): Promise<number> {
  const io: Io = { ...defaultIo(), ...ioIn };
  const args = [...argv];
  const flag = (name: string) => {
    const i = args.indexOf(name);
    if (i < 0) return false;
    args.splice(i, 1);
    return true;
  };
  const option = (name: string) => {
    const i = args.indexOf(name);
    if (i < 0) return undefined;
    const v = args[i + 1];
    args.splice(i, 2);
    return v;
  };
  const yesConsent = flag("--yes-consent") || io.env.KYA_STUDY_CONSENT === "aceito";
  const answersFile = option("--answers");
  const dirOpt = option("--dir");
  const [cmd, arg] = args;
  try {
    switch (cmd) {
      case "init":
        return await init(io, resolve(io.cwd, arg ?? dirOpt ?? "estudo-kya"), yesConsent);
      case "check":
        return await check(io, workspace(io, dirOpt), arg);
      case "finish":
        return await finish(io, workspace(io, dirOpt), answersFile ? resolve(io.cwd, answersFile) : undefined);
      case "report":
        return report(io, workspace(io, dirOpt));
      case undefined:
      case "help":
      case "--help":
      case "-h":
        io.out(HELP);
        return 0;
      default:
        io.err(`comando desconhecido: ${cmd}\n\n${HELP}`);
        return 2;
    }
  } catch (e) {
    io.err(`kya-study: ${(e as Error).message}`);
    return 1;
  }
}

function workspace(io: Io, dir?: string): string {
  const ws = findWorkspace(resolve(io.cwd, dir ?? "."));
  if (!ws) throw new Error("nenhuma pasta do estudo encontrada aqui (rode kya-study init primeiro, ou use --dir)");
  return ws;
}

/** Shows a path with the home directory as "~" (the terminal only; nothing is recorded). */
const show = (p: string) => {
  const h = homedir();
  return h && (p === h || p.startsWith(h + sep)) ? "~" + p.slice(h.length) : p;
};

// ---------------------------------------------------------------- init

async function init(io: Io, ws: string, yesConsent: boolean): Promise<number> {
  if (existsSync(join(ws, STATE_DIR, "config.json"))) {
    io.err(`a pasta ${show(ws)} já tem um estudo iniciado; continue com kya-study check.`);
    return 1;
  }
  if (existsSync(ws) && readdirSync(ws).length) {
    io.err(`a pasta ${show(ws)} já existe e não está vazia; escolha outra (kya-study init <pasta>).`);
    return 1;
  }
  io.out(CONSENT);
  const answer = yesConsent ? "aceito" : (await io.ask(CONSENT_PROMPT)).trim().toLowerCase();
  if (answer !== "aceito") {
    io.out("Tudo bem: nada foi criado nem registrado. Obrigado!");
    return 1;
  }
  const consentAt = new Date().toISOString();
  io.out("\nCriando a pasta de trabalho e a PKI de teste (alguns segundos)...");

  const p = paths(ws);
  mkdirSync(p.src, { recursive: true });
  mkdirSync(p.pki, { recursive: true });
  mkdirSync(join(ws, STATE_DIR), { recursive: true });

  const pki = await makeTestPki();
  writeFileSync(join(p.pki, "LEIA-ME.txt"), `${WARNING}\n`);
  writeFileSync(join(p.pki, "anchors.pem"), pki.anchorsPem);
  writeFileSync(join(p.pki, "ac.crl"), pki.crlDer);
  writeFileSync(join(p.pki, "empresa.pfx"), pki.companyPfx);
  writeFileSync(join(p.pki, "representante.pfx"), pki.representativePfx);
  writeFileSync(join(p.pki, "agente.json"), JSON.stringify({ aviso: WARNING, ...pki.agent }, null, 2) + "\n");
  writeFileSync(join(p.pki, "pki.json"), JSON.stringify({ aviso: WARNING, senha: TEST_PASSWORD, cnpj: COMPANY_CNPJ, cpf_representante: REPRESENTATIVE_CPF, url_lcr: CRL_URL }, null, 2) + "\n");
  writeFileSync(p.ac, JSON.stringify(pki.ac));

  const kit = kitPackage();
  writeFileSync(join(ws, "package.json"), JSON.stringify({
    name: "estudo-kya",
    private: true,
    version: "0.0.0",
    type: "module",
    scripts: { check: "kya-study check", finish: "kya-study finish", report: "kya-study report" },
    dependencies: { "@kya-brasil/core": starterRange("@kya-brasil/core"), "@kya-brasil/agent-tools": starterRange("@kya-brasil/agent-tools") },
    devDependencies: { "@kya-brasil/study-kit": `^${kit.version}` }
  }, null, 2) + "\n");
  writeFileSync(join(ws, ".gitignore"), GITIGNORE);
  writeFileSync(join(ws, "TASKS.md"), tasksMd({ agentId: pki.agent.id }));
  writeFileSync(join(p.src, "emitir.mjs"), STARTER_EMITIR);
  writeFileSync(join(p.src, "verificar.mjs"), STARTER_VERIFICAR);

  const baseline = makeBaseline(ws);
  const cfg: StudyConfig = {
    schema: "kya-study-config/1",
    participant_id: `p-${randomBytes(5).toString("hex")}`,
    kit_version: kit.version,
    started_at: new Date().toISOString(),
    consent_at: consentAt,
    baseline
  };
  writeConfig(ws, cfg);
  io.out(`
Pronto. Seu identificador anônimo: ${cfg.participant_id}

  cd ${show(ws)}
  npm install            (instala @kya-brasil/core, @kya-brasil/agent-tools e o kit)
  leia TASKS.md          (cenário e tarefas)
  npx kya-study check    (quantas vezes quiser)

O relógio do estudo começou agora. ${baseline.method === "git" ? "" : "(git não encontrado: as mudanças serão contadas por um retrato dos arquivos.)"}`.trimEnd());
  return 0;
}

// ---------------------------------------------------------------- check

const TASK_ALIASES: Record<string, TaskId> = { t1: "t1", emitir: "t1", t2: "t2", politica: "t2", "política": "t2", t3: "t3", verificar: "t3", t4: "t4", revogacao: "t4", "revogação": "t4" };
const TASK_TITLE: Record<TaskId, string> = { t1: "T1 · Emitir", t2: "T2 · Política", t3: "T3 · Verificar", t4: "T4 · Revogação" };

async function check(io: Io, ws: string, which?: string): Promise<number> {
  let list: TaskId[] = [...TASKS];
  if (which) {
    const t = TASK_ALIASES[which.toLowerCase()];
    if (!t) {
      io.err(`tarefa desconhecida: ${which} (use t1, t2, t3 ou t4)`);
      return 2;
    }
    list = [t];
  }
  const cfg = readConfig(ws);
  if (cfg.finished_at) io.out("(o estudo já foi encerrado com finish; novas verificações ainda são registradas)");
  const m = loadMaterial(ws);
  let allPass = true;
  for (const t of list) {
    let outcome;
    try {
      outcome = await RUNNERS[t](ws, m);
    } catch (e) {
      // A failure of the kit itself (not of the participant's code) is not logged as an attempt.
      io.err(`${TASK_TITLE[t]}: erro interno do kit: ${(e as Error).message}`);
      allPass = false;
      continue;
    }
    appendAttempt(ws, outcome.attempt);
    const a = outcome.attempt;
    allPass &&= a.pass;
    io.out(`\n${TASK_TITLE[t]}: ${a.pass ? "PASSOU" : "ainda não"}`);
    for (const line of outcome.feedback) io.out(line.startsWith(" ") ? line : `  ${line}`);
    if (!a.pass && a.error_category && !a.not_implemented) io.out(`  categoria: ${CATEGORY_PT[a.error_category]}. Dica: ${HINT_PT[a.error_category]}`);
  }
  io.out(allPass ? "\nTudo certo nestas tarefas." : "\nAjuste o código e rode o check de novo quando quiser.");
  return allPass ? 0 : 1;
}

// ---------------------------------------------------------------- finish

async function finish(io: Io, ws: string, answersFile?: string): Promise<number> {
  let answers: Answers;
  if (answersFile) {
    const a = JSON.parse(readFileSync(answersFile, "utf8")) as Partial<Answers>;
    answers = { q1: a.q1 ?? "", q2: a.q2 ?? "", q3: a.q3 ?? "", q4: a.q4 ?? "", q5: a.q5 ?? "", library_changed: a.library_changed ?? null, library_where: a.library_where ?? "", library_request: a.library_request ?? "", answered_at: new Date().toISOString() };
  } else {
    io.out("\nPerguntas finais (responda em uma linha cada; seja tão breve ou detalhado quanto quiser).\n");
    const got: Record<string, string> = {};
    for (const q of QUESTIONS) {
      let v = (await io.ask(`${q.text}\n> `)).trim();
      while (!v && !q.optional) v = (await io.ask("  (resposta obrigatória; escreva \"nada\" se não houver)\n> ")).trim();
      got[q.id] = v;
    }
    let changed: boolean | null = null;
    for (let i = 0; i < 3 && changed === null; i++) {
      const v = (await io.ask(`${LIBRARY_QUESTIONS.changed}\n> `)).trim().toLowerCase();
      if (/^(s|sim|y|yes)$/.test(v)) changed = true;
      else if (/^(n|nao|não|no)$/.test(v)) changed = false;
    }
    const where = changed ? (await io.ask(`${LIBRARY_QUESTIONS.where}\n> `)).trim() : "";
    const request = (await io.ask(`${LIBRARY_QUESTIONS.request}\n> `)).trim();
    answers = { q1: got.q1 ?? "", q2: got.q2 ?? "", q3: got.q3 ?? "", q4: got.q4 ?? "", q5: got.q5 ?? "", library_changed: changed, library_where: where, library_request: request, answered_at: new Date().toISOString() };
  }
  writeFileSync(paths(ws).answers, JSON.stringify(answers, null, 2) + "\n");
  const cfg = readConfig(ws);
  cfg.finished_at ??= new Date().toISOString();
  writeConfig(ws, cfg);
  io.out("\nRespostas salvas nesta pasta. Agora gere o relatório: npx kya-study report");
  return 0;
}

// ---------------------------------------------------------------- report

function report(io: Io, ws: string): number {
  const { file, report: r } = writeReport(ws);
  if (!r.finished) io.out("(você ainda não rodou kya-study finish: o relatório sai sem as respostas abertas)");
  io.out(`
Relatório anônimo gravado em:

  ${show(file)}

Ele não contém código, nomes, caminhos nem dados da máquina; abra e confira se quiser.
Envie este arquivo ao pesquisador pelo canal combinado. Obrigado pela participação!`);
  return 0;
}
