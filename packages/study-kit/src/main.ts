/**
 * kya-study: init | check [task] | finish | report. Every command works on the local workspace only.
 * Hidden flags for automated tests: init --yes-consent (or KYA_STUDY_CONSENT=aceito), finish --answers <file.json>.
 */
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve, sep } from "node:path";
import { type Interface, createInterface } from "node:readline";
import { GITIGNORE, makeBaseline } from "./diffstats.js";
import { COMPANY_CNPJ, CRL_URL, REPRESENTATIVE_CPF, TEST_PASSWORD, WARNING, makeTestPki } from "./pki.js";
import { type Answers, writeReport } from "./report.js";
import { trackLibrary } from "./integrity.js";
import { RUNNERS, loadMaterial } from "./tasks.js";
import { AI_QUESTIONS, CATEGORY_PT, CONSENT, CONSENT_PROMPT, HINT_PT, LIBRARY_QUESTIONS, QUESTIONS, STARTER_EMITIR, STARTER_VERIFICAR, tasksMd } from "./texts.js";
import { STATE_DIR, TASKS, type StudyConfig, type TaskId, appendAttempt, findWorkspace, kitPackage, kitSpec, paths, readConfig, starterRange, writeConfig } from "./workspace.js";

export interface Io {
  cwd: string;
  env: Record<string, string | undefined>;
  out: (s: string) => void;
  err: (s: string) => void;
  /** Asks one question in the terminal and returns the answer (without the newline), or null when the input ended. */
  ask: (q: string) => Promise<string | null>;
  /** True after Ctrl-C in a question: the command stops without saving anything. */
  interrupted?: () => boolean;
  /** Releases the terminal (an open readline keeps the process alive). */
  close?: () => void;
}

function defaultIo(): Io {
  let rl: Interface | null = null;
  let closed = false;
  let waiting: ((v: string | null) => void) | null = null;
  let lines: string[] | null = null;
  let interrupted = false;
  const typed: string[] = [];
  return {
    interrupted: () => interrupted,
    cwd: process.cwd(),
    env: process.env,
    out: (s) => process.stdout.write(s + "\n"),
    err: (s) => process.stderr.write(s + "\n"),
    ask: async (q) => {
      if (process.stdin.isTTY) {
        if (closed) return null;
        if (!rl) {
          rl = createInterface({ input: process.stdin, output: process.stdout });
          // Ctrl-C: interrupted (nothing is saved); Ctrl-D: the input ended. Either way a pending question answers null.
          rl.on("SIGINT", () => {
            interrupted = true;
            rl?.close();
          });
          // Lines typed (or pasted) before the next question are kept for it, never dropped.
          rl.on("line", (line) => {
            const w = waiting;
            waiting = null;
            if (w) w(line);
            else typed.push(line);
          });
          rl.on("close", () => {
            closed = true;
            waiting?.(null);
            waiting = null;
          });
        }
        if (typed.length) {
          const line = typed.shift()!;
          process.stdout.write(`${q}${line}\n`);
          return line;
        }
        return new Promise((resolve) => {
          waiting = resolve;
          rl!.setPrompt(q);
          rl!.prompt();
        });
      }
      // Piped input: read it all once, one answer per line; null after the last line (EOF).
      if (!lines) {
        const chunks: Buffer[] = [];
        for await (const c of process.stdin) chunks.push(c as Buffer);
        const text = Buffer.concat(chunks).toString("utf8");
        lines = text ? text.replace(/\r?\n$/, "").split(/\r?\n/) : [];
      }
      process.stdout.write(q + "\n");
      return lines.length ? lines.shift()! : null;
    },
    close: () => {
      closed = true;
      rl?.close();
      rl = null;
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
  try {
    return await run(argv, io);
  } finally {
    io.close?.();
  }
}

async function run(argv: string[], io: Io): Promise<number> {
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
  const kit = option("--kit") ?? io.env.KYA_STUDY_KIT_SPEC;
  const dirOpt = option("--dir");
  const [cmd, arg] = args;
  try {
    switch (cmd) {
      case "init":
        return await init(io, resolve(io.cwd, arg ?? dirOpt ?? "estudo-kya"), yesConsent, kit);
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

async function init(io: Io, ws: string, yesConsent: boolean, kitOverride?: string): Promise<number> {
  if (existsSync(join(ws, STATE_DIR, "config.json"))) {
    io.err(`a pasta ${show(ws)} já tem um estudo iniciado; continue com kya-study check.`);
    return 1;
  }
  if (existsSync(ws) && readdirSync(ws).length) {
    io.err(`a pasta ${show(ws)} já existe e não está vazia; escolha outra (kya-study init <pasta>).`);
    return 1;
  }
  io.out(CONSENT);
  const answer = yesConsent ? "aceito" : ((await io.ask(CONSENT_PROMPT)) ?? "").trim().toLowerCase();
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
    devDependencies: { "@kya-brasil/study-kit": kitSpec(kitOverride) }
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
  const libNote = trackLibrary(ws);
  if (libNote) io.out(libNote);
  let allPass = true;
  for (const t of list) {
    let outcome;
    try {
      outcome = await RUNNERS[t](m);
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
  let ended = false;
  if (answersFile) {
    const a = JSON.parse(readFileSync(answersFile, "utf8")) as Partial<Answers>;
    answers = {
      q1: a.q1 ?? "", q2: a.q2 ?? "", q3: a.q3 ?? "", q4: a.q4 ?? "", q5: a.q5 ?? "",
      ai_used: a.ai_used ?? null, ai_tasks: normalizeTasks(a.ai_tasks ?? []),
      library_changed: a.library_changed ?? null, library_where: a.library_where ?? "", library_request: a.library_request ?? "",
      answered_at: new Date().toISOString()
    };
  } else {
    const previous = existsSync(paths(ws).answers);
    const stopped = () => io.interrupted?.() === true;
    if (previous) {
      const v = await io.ask("Você já respondeu às perguntas finais. Responder de novo substitui as respostas anteriores. Continuar? (s/n)\n> ");
      if (stopped() || v === null || !/^(s|sim|y|yes)$/i.test(v.trim())) {
        io.out("\nNada mudou: as respostas anteriores continuam salvas. Gere o relatório com: npx kya-study report");
        return stopped() ? 130 : 0;
      }
    }
    // Every question stops at the end of the input (EOF): unanswered ones stay empty.
    const ask = async (q: string): Promise<string | null> => {
      if (ended) return null;
      const v = await io.ask(q);
      if (v === null) ended = true;
      return v === null ? null : v.trim();
    };
    const yesNo = async (q: string): Promise<boolean | null> => {
      for (let i = 0; i < 3; i++) {
        const v = (await ask(`${q}\n> `))?.toLowerCase();
        if (v === undefined || v === null) return null;
        if (/^(s|sim|y|yes)$/.test(v)) return true;
        if (/^(n|nao|não|no)$/.test(v)) return false;
      }
      return null;
    };
    io.out("\nPerguntas finais. Responda em uma linha cada, com o máximo de detalhe que puder: onde travou, o que procurou,\no que faltou na documentação. É a parte mais importante do estudo.\n");
    const got: Record<string, string> = {};
    for (const q of QUESTIONS) {
      let v = await ask(`${q.text}\n> `);
      while (v === "" && !q.optional) v = await ask("  (resposta obrigatória; escreva \"nada\" se não houver)\n> ");
      got[q.id] = v ?? "";
    }
    const aiUsed = await yesNo(AI_QUESTIONS.used);
    const aiTasks = aiUsed ? normalizeTasks(((await ask(`${AI_QUESTIONS.tasks}\n> `)) ?? "").split(/[\s,;]+/)) : [];
    const changed = await yesNo(LIBRARY_QUESTIONS.changed);
    const where = changed ? ((await ask(`${LIBRARY_QUESTIONS.where}\n> `)) ?? "") : "";
    const request = (await ask(`${LIBRARY_QUESTIONS.request}\n> `)) ?? "";
    answers = {
      q1: got.q1 ?? "", q2: got.q2 ?? "", q3: got.q3 ?? "", q4: got.q4 ?? "", q5: got.q5 ?? "",
      ai_used: aiUsed, ai_tasks: aiTasks,
      library_changed: changed, library_where: where, library_request: request,
      answered_at: new Date().toISOString()
    };
    if (stopped()) {
      io.out("\nInterrompido: nada foi salvo. Rode npx kya-study finish de novo quando quiser.");
      return 130;
    }
    if (ended && previous) {
      io.out("\n(a entrada terminou antes do fim: as respostas anteriores continuam salvas)");
      return 0;
    }
    if (ended) io.out("\n(a entrada terminou: as perguntas restantes ficaram em branco)");
  }
  writeFileSync(paths(ws).answers, JSON.stringify(answers, null, 2) + "\n");
  const cfg = readConfig(ws);
  cfg.finished_at ??= new Date().toISOString();
  writeConfig(ws, cfg);
  io.out("\nRespostas salvas nesta pasta. Agora gere o relatório: npx kya-study report");
  return 0;
}

/** "t1, T3 e 4" -> ["t1", "t3", "t4"]: only task ids, nothing else the participant typed. */
function normalizeTasks(v: unknown): TaskId[] {
  const items = Array.isArray(v) ? v.map(String) : [String(v ?? "")];
  const out = new Set<TaskId>();
  if (items.some((it) => /\b(todas|todos|all)\b/i.test(it))) return [...TASKS];
  for (const it of items) for (const m of it.toLowerCase().matchAll(/t?([1-4])/g)) out.add(`t${m[1]}` as TaskId);
  return TASKS.filter((t) => out.has(t));
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
