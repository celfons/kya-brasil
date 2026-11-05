/**
 * Automatic grading of the four tasks. The participant's modules (src/emitir.mjs, src/verificar.mjs) run in a
 * child process with a timeout per call (sandbox.ts); every result is checked with the library itself. Nothing
 * here touches the network.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { assembleCredential, buildMandate, mandateSigningInput, openPfx, verifySelfIssuedCredential } from "@kya-brasil/core";
import { signRequest } from "@kya-brasil/agent-tools";
import { generatePrivateKey } from "viem/accounts";
import { type ErrorCategory, categorize, categorizeSelfIssuedRule, categorizeThrown } from "./errors.js";
import { COMPANY_CNPJ, CRL_URL, TEST_PASSWORD, makeCrl, makeTestPki, pemBlocks, type TestPki } from "./pki.js";
import { type PolicyResult, SCENARIO, gradePolicy, referenceMandate } from "./policy.js";
import { type CallResult, type ErrorInfo, Sandbox, callTimeoutMs } from "./sandbox.js";
import { type Attempt, STATE_DIR, type SubCase, type TaskId, paths, readConfig, writeConfig } from "./workspace.js";

const MIN = 60_000;
const DAY = 86_400_000;

export interface TaskOutcome {
  attempt: Attempt;
  /** Lines of PT-BR feedback for the terminal (never logged: they may quote the participant's errors and paths). */
  feedback: string[];
}

export interface Material {
  ws: string;
  anchors: string[];
  companyPfx: Uint8Array;
  agent: { kind: "evm"; id: `0x${string}`; privateKey: `0x${string}` };
  ac: TestPki["ac"];
}

export function loadMaterial(ws: string): Material {
  const p = paths(ws);
  return {
    ws,
    anchors: pemBlocks(readFileSync(join(p.pki, "anchors.pem"), "utf8")),
    companyPfx: new Uint8Array(readFileSync(join(p.pki, "empresa.pfx"))),
    agent: JSON.parse(readFileSync(join(p.pki, "agente.json"), "utf8")),
    ac: JSON.parse(readFileSync(p.ac, "utf8"))
  };
}

/**
 * A second throwaway PKI whose root is NOT in the participant's anchors, with a company certificate for the same
 * CNPJ (T3: a verifier must refuse a credential that does not chain to its anchors). Made once, kept in .kya-study.
 */
async function untrustedPki(ws: string): Promise<{ anchors: string[]; companyPfx: Uint8Array }> {
  const f = join(ws, STATE_DIR, "pki-untrusted.json");
  if (existsSync(f)) {
    const j = JSON.parse(readFileSync(f, "utf8"));
    return { anchors: pemBlocks(j.anchorsPem), companyPfx: new Uint8Array(Buffer.from(j.companyPfx, "base64")) };
  }
  const other = await makeTestPki();
  writeFileSync(f, JSON.stringify({ anchorsPem: other.anchorsPem, companyPfx: Buffer.from(other.companyPfx).toString("base64") }));
  return { anchors: pemBlocks(other.anchorsPem), companyPfx: other.companyPfx };
}

const round = (ms: number) => Math.round(ms * 100) / 100;
const mark = (ok: boolean) => (ok ? "  [ok]" : "  [x] ");

function base(task: TaskId): Attempt {
  return { ts: new Date().toISOString(), task, pass: false, error_category: null, error_categories: [], verify_ms: [], accept_ms: [] };
}
function failWith(a: Attempt, cat: ErrorCategory) {
  if (!a.error_categories.includes(cat)) a.error_categories.push(cat);
  a.error_category ??= cat;
}

// ---------------------------------------------------------------- describing the participant's failures

const notImplemented = (e: ErrorInfo | null) => !!e && /NAO_IMPLEMENTADO/.test(e.message);

/** Paths in the terminal: relative to the workspace (file:// URLs too). */
function rel(ws: string, text: string): string {
  let s = text;
  for (const prefix of [`file://${ws}${sep}`, `${ws}${sep}`]) s = s.split(prefix).join("");
  try {
    const url = new URL(`file://${ws}/`).href;
    s = s.split(url).join("");
  } catch { /* ignore */ }
  return s;
}

/** Where in the participant's files an error happened: "src/x.mjs:12:5", from the stack or `node --check`. */
function locate(ws: string, e: ErrorInfo): string | null {
  const src = join(ws, "src");
  for (const line of e.stack.split("\n")) {
    const m = /(?:file:\/\/)?(\/[^\s():]+|[A-Za-z]:\\[^\s():]+):(\d+)(?::(\d+))?/.exec(line);
    if (m) {
      let file = m[1]!;
      try {
        file = fileURLToPath(`file://${file}`);
      } catch { /* keep */ }
      if (file.startsWith(src)) return `${relative(ws, file).split(sep).join("/")}:${m[2]}${m[3] ? `:${m[3]}` : ""}`;
    }
  }
  if (e.name === "SyntaxError") {
    // Node does not put the location of a syntax error in an imported module's stack: ask `node --check`.
    for (const name of existsSync(src) ? readdirSync(src) : []) {
      if (!/\.(m?js|cjs)$/.test(name)) continue;
      const r = spawnSync(process.execPath, ["--check", join(src, name)], { encoding: "utf8" });
      if (r.status !== 0) {
        const m = /:(\d+)\s*$/m.exec((r.stderr ?? "").split("\n")[0] ?? "");
        return `src/${name}${m ? `:${m[1]}` : ""}`;
      }
    }
  }
  return null;
}

function describeError(ws: string, what: string, e: ErrorInfo): string {
  const where = locate(ws, e);
  const kind = e.name === "SyntaxError" ? "erro de sintaxe" : e.code === "ERR_MODULE_NOT_FOUND" ? "importação não encontrada" : "erro";
  return `${what}: ${kind}${where ? ` em ${where}` : ""}: ${rel(ws, `${e.name !== "Error" && e.name !== "SyntaxError" ? `${e.name}: ` : ""}${e.message}`).split("\n")[0]!.slice(0, 300)}`;
}

/** Category and feedback for a call that did not return normally. */
function failure(ws: string, what: string, r: Exclude<CallResult, { kind: "ok" }>): { cat: ErrorCategory; text: string; notImpl: boolean } {
  if (r.kind === "timeout") return { cat: "timeout", text: `${what}: tempo esgotado (${r.ms / 1000} s sem resposta); o kit interrompeu o seu código`, notImpl: false };
  if (r.kind === "crash") return { cat: "runtime", text: `${what}: ${r.detail}`, notImpl: false };
  if (r.contract) return { cat: "contract", text: `${what}: ${r.contract}`, notImpl: false };
  const ni = notImplemented(r.error);
  return { cat: categorizeThrown(r.error), text: ni ? `${what} ainda não foi implementada.` : describeError(ws, what, r.error), notImpl: ni };
}

// ---------------------------------------------------------------- T1

interface T1Result {
  outcome: TaskOutcome;
  credential: { mandate?: Record<string, unknown>; issued_at?: string; expires_at?: string } | null;
}

async function runIssue(m: Material, task: TaskId): Promise<T1Result> {
  const a = base(task);
  const fb: string[] = [];
  const box = new Sandbox(m.ws);
  let r: CallResult;
  try {
    r = await box.call("issue", { ctx: { pfx: new Uint8Array(m.companyPfx), senha: TEST_PASSWORD, cnpj: COMPANY_CNPJ, agente: { kind: "evm", id: m.agent.id }, anchors: [...m.anchors], agora: Date.now() } }, callTimeoutMs() * 3);
  } finally {
    box.kill();
  }
  if (r.kind !== "ok") {
    const f = failure(m.ws, "emitirCredencial", r);
    if (f.notImpl) a.not_implemented = true;
    failWith(a, f.cat);
    fb.push(f.text);
    if (f.cat === "icp_chain") fb.push("o .pfx não abriu ou o certificado não pôde ser lido: confira ctx.pfx e ctx.senha.");
    return { outcome: { attempt: a, feedback: fb }, credential: null };
  }
  const out = r.value.value as { credential: Parameters<typeof verifySelfIssuedCredential>[0]["credential"]; proof: Parameters<typeof verifySelfIssuedCredential>[0]["proof"] };
  const t0 = performance.now();
  const v = await verifySelfIssuedCredential({ credential: out.credential, proof: out.proof, anchors: m.anchors, now: new Date() });
  a.verify_ms.push(round(performance.now() - t0));
  for (const c of v.checks.filter((x) => !x.ok)) {
    failWith(a, categorizeSelfIssuedRule(c.rule, c.detail));
    fb.push(`a credencial não verifica (${c.rule}): ${c.detail}`);
  }
  if (v.ok && String((out.credential as { agent?: { id?: unknown } }).agent?.id ?? "").toLowerCase() !== m.agent.id.toLowerCase()) {
    failWith(a, "other");
    fb.push("a credencial é válida, mas não é do agente de pki/agente.json (use ctx.agente).");
  }
  a.pass = a.error_categories.length === 0;
  if (a.pass && task === "t1") fb.push("credencial emitida e verificada: assinatura, cadeia até as âncoras de teste, mandato e validade conferem.");
  return { outcome: { attempt: a, feedback: fb }, credential: a.pass ? (out.credential as T1Result["credential"]) : null };
}

export async function runT1(m: Material): Promise<TaskOutcome> {
  return (await runIssue(m, "t1")).outcome;
}

// ---------------------------------------------------------------- T2

const DIR_PT: Record<string, string> = { permissive: "mais permissivo", restrictive: "mais restritivo", neutral: "fora do cenário" };
const GRADE_PT: Record<PolicyResult["grade"], string> = { correct: "correta", permissive: "permissiva demais", restrictive: "restritiva demais", invalid: "inválida" };

export async function runT2(m: Material): Promise<TaskOutcome> {
  const issued = await runIssue(m, "t2");
  const a = issued.outcome.attempt;
  const result = gradePolicy(issued.credential, a.pass);
  a.policy = result;
  const fb: string[] = [];
  if (result.grade === "invalid") {
    a.pass = false;
    if (!a.error_categories.length) failWith(a, "other");
    fb.push("política inválida: a T1 precisa emitir uma credencial que verifique.", ...issued.outcome.feedback);
  } else {
    a.pass = result.grade === "correct";
    if (!a.pass) failWith(a, "mandate");
    fb.push(`política ${GRADE_PT[result.grade]}.`);
    for (const d of result.deviations) fb.push(`  - ${d.field}: ${DIR_PT[d.direction]} que o cenário (${d.detail})`);
  }
  return { attempt: a, feedback: fb };
}

// ---------------------------------------------------------------- T3 / T4 (the participant's verifier)

const URL_PEDIDOS = "https://marketplace.exemplo.invalid/api/pedidos";
type Issued = Awaited<ReturnType<typeof assembleCredential>>;
interface Req {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

/** A credential built from the answer key (T3 and T4 do not depend on T1), signed by the given company .pfx. */
async function referenceCredential(m: Material, now: Date, signer: { companyPfx: Uint8Array; anchors: string[] } = m): Promise<Issued> {
  const built = await buildMandate({ credential_id: crypto.randomUUID(), agent: { kind: m.agent.kind, id: m.agent.id }, principal: { kind: "company", cnpj: COMPANY_CNPJ }, mandate: referenceMandate(now), ttl_seconds: SCENARIO.validityDays * 86_400, now });
  const { text } = await mandateSigningInput(built);
  const company = await openPfx(signer.companyPfx, TEST_PASSWORD);
  return assembleCredential(built, await company.sign(text), [], { anchors: signer.anchors, now });
}

async function purchase(m: Material, cred: Issued, p: { valor: number; fornecedor: string; now: Date; key?: `0x${string}`; sendBody?: (body: Record<string, unknown>) => Record<string, unknown> }): Promise<Req> {
  const order = { pedido: crypto.randomUUID(), acao: SCENARIO.action, valor: p.valor, moeda: SCENARIO.currency, fornecedor: p.fornecedor };
  const body = JSON.stringify(order);
  const headers = await signRequest({ credentialId: cred.credential.credential_id, key: { kind: "evm", privateKey: p.key ?? m.agent.privateKey }, method: "POST", url: URL_PEDIDOS, body, now: p.now, present: { credential: cred.credential, proof: cred.proof } });
  return { url: URL_PEDIDOS, method: "POST", headers: { ...headers, "content-type": "application/json" }, body: p.sendBody ? JSON.stringify(p.sendBody(order)) : body };
}

const b64url = (s: string) => Buffer.from(s, "utf8").toString("base64url");
const fromB64url = (s: string) => Buffer.from(s, "base64url").toString("utf8");

/** Flips one character of the request signature (same length, still well-formed hex). */
function tamperSignature(r: Req): Req {
  const sig = r.headers["kya-signature"] ?? "";
  const i = Math.max(2, sig.length - 6);
  const c = sig[i] ?? "0";
  const flipped = c === "a" ? "b" : c === "A" ? "B" : /[0-9]/.test(c) ? String((Number(c) + 1) % 10) : "a";
  return { ...r, headers: { ...r.headers, "kya-signature": sig.slice(0, i) + flipped + sig.slice(i + 1) } };
}

/** The credential document with a larger ceiling than the one the company signed. */
function tamperMandate(r: Req): Req {
  const doc = JSON.parse(fromB64url(r.headers["kya-credential-document"] ?? ""));
  doc.mandate.max_per_operation = { amount: 5000, currency: SCENARIO.currency };
  return { ...r, headers: { ...r.headers, "kya-credential-document": b64url(JSON.stringify(doc)) } };
}

interface Call {
  accepted: boolean;
  reason: string;
  /** Set when the call did not return a well-formed answer. */
  failure: { cat: ErrorCategory; text: string; notImpl: boolean } | null;
  ms: number | null;
}

class Verifier {
  private box: Sandbox;
  constructor(private m: Material) {
    this.box = new Sandbox(m.ws);
  }
  async create(clock: number | null, crl: Uint8Array): Promise<Call["failure"]> {
    const s = await this.box.call("state", { clock, crl }, callTimeoutMs() * 3);
    const r = s.kind === "ok" ? await this.box.call("verifier", { anchors: [...this.m.anchors] }, callTimeoutMs() * 3) : s;
    return r.kind === "ok" ? null : failure(this.m.ws, "criarVerificador", r);
  }
  async state(clock: number | null, crl: Uint8Array) {
    await this.box.call("state", { clock, crl });
  }
  async verify(a: Attempt, req: Req): Promise<Call> {
    const r = await this.box.call("verify", { req });
    if (r.kind !== "ok") return { accepted: false, reason: "", failure: failure(this.m.ws, "verificador", r), ms: null };
    const v = r.value.value as { shapeOk: boolean; aceito: boolean | null; motivo: string; ms: number };
    a.verify_ms.push(round(v.ms));
    if (!v.shapeOk) return { accepted: false, reason: "", failure: { cat: "contract", text: "o verificador deve devolver { aceito: boolean, motivo?: string }", notImpl: false }, ms: v.ms };
    return { accepted: v.aceito === true, reason: v.motivo, failure: null, ms: v.ms };
  }
  close() {
    this.box.kill();
  }
}

const describe = (c: Call) => (c.failure ? c.failure.text : c.accepted ? "aceito" : `recusado${c.reason ? ` (${c.reason.slice(0, 120)})` : ""}`);
const wrongCategory = (c: Call, whenAccepted: ErrorCategory): ErrorCategory => (c.failure ? c.failure.cat : c.accepted ? whenAccepted : categorize(c.reason));

/** The kit issues a fresh CRL at each check (it holds the test AC's key), so T3 never fails because pki/ac.crl aged. */
const freshCrl = (m: Material, now: number) => makeCrl(m.ac, { thisUpdate: new Date(now - MIN), nextUpdate: new Date(now + 7 * DAY), revokeCompany: false });

export async function runT3(m: Material): Promise<TaskOutcome> {
  const a = base("t3");
  const fb: string[] = [];
  const t = Date.now();
  const now = new Date(t);
  const cred = await referenceCredential(m, now);
  const untrusted = await referenceCredential(m, now, await untrustedPki(m.ws));
  const v = new Verifier(m);
  try {
    const created = await v.create(null, await freshCrl(m, t));
    if (created) {
      if (created.notImpl) a.not_implemented = true;
      failWith(a, created.cat);
      fb.push(created.text);
      return { attempt: a, feedback: fb };
    }
    const valid = await purchase(m, cred, { valor: 120, fornecedor: SCENARIO.supplierCnpj, now });
    const subs: SubCase[] = [];
    const first = await v.verify(a, valid);
    if (first.failure?.notImpl) a.not_implemented = true;
    const okFirst = first.accepted && !first.failure;
    if (okFirst && first.ms !== null) a.accept_ms!.push(round(first.ms));
    subs.push({ id: "compra_valida", expected: "accept", pass: okFirst, category: okFirst ? null : wrongCategory(first, "other") });
    fb.push(`${mark(okFirst)} compra de R$ 120 do fornecedor X: ${describe(first)}${okFirst ? "" : " (esperado: aceitar)"}`);

    const cases: [string, string, () => Promise<Req>, ErrorCategory][] = [
      ["acima_do_teto", "compra de R$ 800 (acima do teto por compra)", () => purchase(m, cred, { valor: 800, fornecedor: SCENARIO.supplierCnpj, now }), "mandate"],
      ["fornecedor_errado", "compra de R$ 100 de outro fornecedor", () => purchase(m, cred, { valor: 100, fornecedor: SCENARIO.otherSupplierCnpj, now }), "mandate"],
      ["assinatura_adulterada", "requisição com a assinatura adulterada", async () => tamperSignature(await purchase(m, cred, { valor: 90, fornecedor: SCENARIO.supplierCnpj, now })), "signature"],
      ["corpo_alterado", "corpo alterado depois de assinado (R$ 120 assinado, R$ 50 enviado)", () => purchase(m, cred, { valor: 120, fornecedor: SCENARIO.supplierCnpj, now, sendBody: (b) => ({ ...b, valor: 50 }) }), "signature"],
      ["ac_nao_confiavel", "credencial de uma AC fora das âncoras", () => purchase(m, untrusted, { valor: 80, fornecedor: SCENARIO.supplierCnpj, now }), "icp_chain"],
      ["chave_errada", "requisição assinada por outra chave, não a do agente", () => purchase(m, cred, { valor: 70, fornecedor: SCENARIO.supplierCnpj, now, key: generatePrivateKey() }), "signature"],
      // Within the signed ceiling, so only the proof (the e-CNPJ signature over the mandate) can catch it.
      ["mandato_adulterado", "credencial com o teto adulterado para R$ 5.000 (compra de R$ 300)", async () => tamperMandate(await purchase(m, cred, { valor: 300, fornecedor: SCENARIO.supplierCnpj, now })), "icp_chain"],
      ["repeticao", "a mesma requisição da compra de R$ 120, repetida", async () => valid, "replay"]
    ];
    for (const [id, label, make, whenAccepted] of cases) {
      const c = await v.verify(a, await make());
      // A refusal only counts when the valid purchase was accepted: a verifier that refuses everything scores nothing.
      const pass = !c.accepted && !c.failure && okFirst;
      subs.push({ id, expected: "refuse", pass, category: pass ? null : c.accepted || c.failure ? wrongCategory(c, whenAccepted) : (subs[0]!.category ?? "other") });
      fb.push(`${mark(pass)} ${label}: ${describe(c)}${pass ? "" : okFirst ? " (esperado: recusar)" : " (só conta depois que a compra válida for aceita)"}`);
    }
    a.sub_cases = subs;
    for (const s of subs) if (!s.pass && s.category) failWith(a, s.category);
    a.pass = subs.every((s) => s.pass);
    return { attempt: a, feedback: fb };
  } finally {
    v.close();
  }
}

export async function runT4(m: Material): Promise<TaskOutcome> {
  const a = base("t4");
  const fb: string[] = [];
  const t = Date.now();
  // Three CRLs: the current one, the same contents re-issued later (bytes change, nothing revoked), and the one that
  // revokes the company's certificate. Each step moves the verifier's clock past the previous CRL's nextUpdate.
  const crlA = await makeCrl(m.ac, { thisUpdate: new Date(t - MIN), nextUpdate: new Date(t + 10 * MIN), revokeCompany: false });
  const crlB = await makeCrl(m.ac, { thisUpdate: new Date(t + 11 * MIN), nextUpdate: new Date(t + 20 * MIN), revokeCompany: false });
  const crlC = await makeCrl(m.ac, { thisUpdate: new Date(t + 21 * MIN), nextUpdate: new Date(t + 7 * DAY), revokeCompany: true, revokedAt: new Date(t + 21 * MIN) });
  const cred = await referenceCredential(m, new Date(t));
  const v = new Verifier(m);
  const subs: SubCase[] = [];
  const cfg = readConfig(m.ws);
  try {
    const created = await v.create(t, crlA);
    if (created) {
      if (created.notImpl) a.not_implemented = true;
      failWith(a, created.cat);
      fb.push(created.text);
      return { attempt: a, feedback: fb };
    }
    const step = async (id: string, label: string, clock: number, crl: Uint8Array, expect: "accept" | "revoked") => {
      await v.state(clock, crl);
      const c = await v.verify(a, await purchase(m, cred, { valor: 100, fornecedor: SCENARIO.supplierCnpj, now: new Date(clock) }));
      if (c.failure?.notImpl) a.not_implemented = true;
      let pass: boolean, category: ErrorCategory | null;
      if (expect === "accept") {
        pass = c.accepted && !c.failure;
        if (pass && c.ms !== null) a.accept_ms!.push(round(c.ms));
        category = pass ? null : wrongCategory(c, "other");
      } else {
        const reason = c.failure || c.accepted ? null : categorize(c.reason);
        pass = reason === "revocation";
        category = pass ? null : c.accepted ? "revocation" : c.failure ? c.failure.cat : (reason ?? "other");
      }
      subs.push({ id, expected: expect === "accept" ? "accept" : "refuse", pass, category });
      fb.push(`${mark(pass)} ${label}: ${describe(c)}${pass ? "" : expect === "accept" ? " (esperado: aceitar)" : c.accepted ? " (esperado: recusar por revogação)" : " (esperado: recusar com o código de erro de revogação em motivo)"}`);
      return pass;
    };
    const blocked = (id: string, why: string) => {
      subs.push({ id, expected: id === "depois_da_revogacao" ? "refuse" : "accept", pass: false, category: subs.find((s) => !s.pass)?.category ?? "other" });
      fb.push(`  ${why}`);
    };
    if (!(await step("antes_da_revogacao", "LCR atual, compra de R$ 100", t, crlA, "accept"))) {
      blocked("lcr_reemitida", "a LCR reemitida só é publicada depois que a compra anterior for aceita.");
      blocked("depois_da_revogacao", "a LCR revogada também.");
    } else if (!(await step("lcr_reemitida", "LCR reemitida sem revogação nova, relógio +12 min, compra de R$ 100", t + 12 * MIN, crlB, "accept"))) {
      blocked("depois_da_revogacao", "a LCR revogada só é publicada depois que a compra com a LCR reemitida for aceita.");
    } else {
      // The revoked CRL is "published" once the verifier has handled the first two steps; the timer starts here.
      if (!cfg.t4_published_at) {
        cfg.t4_published_at = new Date().toISOString();
        writeConfig(m.ws, cfg);
      }
      await step("depois_da_revogacao", "LCR que revoga o certificado da empresa, relógio +22 min, compra de R$ 100", t + 22 * MIN, crlC, "revoked");
    }
  } finally {
    v.close();
  }
  a.sub_cases = subs;
  a.t4_published_at = cfg.t4_published_at ?? null;
  for (const s of subs) if (!s.pass && s.category) failWith(a, s.category);
  a.pass = subs.length === 3 && subs.every((s) => s.pass);
  if (a.pass) fb.push(`  (a LCR do certificado é ${CRL_URL})`);
  return { attempt: a, feedback: fb };
}

export const RUNNERS: Record<TaskId, (m: Material) => Promise<TaskOutcome>> = { t1: runT1, t2: runT2, t3: runT3, t4: runT4 };
