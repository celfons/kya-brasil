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
import { randomInt } from "node:crypto";
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
  // JSON.parse also throws SyntaxError, at run time: only a module that does not parse is a syntax error.
  const kind = e.name === "SyntaxError" && !/JSON/.test(e.message) ? "erro de sintaxe" : e.code === "ERR_MODULE_NOT_FOUND" ? "importação não encontrada" : "erro";
  return `${what}: ${kind}${where ? ` em ${where}` : ""}: ${rel(ws, `${e.name !== "Error" && e.name !== "SyntaxError" ? `${e.name}: ` : ""}${e.message}`).split("\n")[0]!.slice(0, 300)}`;
}

/** Category and feedback for a call that did not return normally. */
function failure(ws: string, what: string, r: Exclude<CallResult, { kind: "ok" }>): { cat: ErrorCategory; text: string; notImpl: boolean } {
  if (r.kind === "timeout") return { cat: "timeout", text: `${what}: tempo esgotado (${r.ms / 1000} s sem resposta); o kit interrompeu o seu código`, notImpl: false };
  if (r.kind === "crash") return { cat: "runtime", text: `${what}: ${r.detail}`, notImpl: false };
  if (r.contract) return { cat: "contract", text: `${what}: ${r.contract}`, notImpl: false };
  const ni = notImplemented(r.error);
  return { cat: categorizeThrown(r.error), text: ni ? `${what}: ainda não implementado.` : describeError(ws, what, r.error), notImpl: ni };
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

const DIR_PT: Record<string, string> = { permissive: "mais permissivo que o cenário", restrictive: "mais restritivo que o cenário", neutral: "diferente do cenário" };
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
    for (const d of result.deviations) fb.push(`  - ${d.field}: ${DIR_PT[d.direction]} (${d.detail})`);
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

const rnd = (lo: number, hi: number) => randomInt(lo, hi + 1);
function shuffle<T>(xs: T[]): T[] {
  for (let i = xs.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [xs[i], xs[j]] = [xs[j]!, xs[i]!];
  }
  return xs;
}

interface T3Case {
  id: string;
  label: string;
  expected: "accept" | "refuse";
  req: () => Promise<Req>;
  /** Category recorded when a request that must be refused is accepted. */
  whenAccepted: ErrorCategory;
  /** For the replay: the valid purchase it repeats (it must be sent after it). */
  after?: T3Case;
}

/**
 * T3. Three valid purchases (random amounts) and eight that must be refused, sent in a random order (the replay
 * always after the purchase it repeats), so only a verifier that really checks each request passes: one that
 * accepts "the first request" or counts calls does not. A refusal counts only when every valid purchase was
 * accepted.
 */
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
    const once = (make: () => Promise<Req>) => {
      let r: Promise<Req> | null = null;
      return () => (r ??= make());
    };
    const ok = (valor: number, extra: Partial<Parameters<typeof purchase>[2]> = {}) => once(() => purchase(m, cred, { valor, fornecedor: SCENARIO.supplierCnpj, now, ...extra }));
    const valids: T3Case[] = [0, 1, 2].map(() => {
      const valor = rnd(60, 400);
      return { id: "compra_valida", label: `compra de R$ ${valor} do fornecedor X`, expected: "accept", req: ok(valor), whenAccepted: "other" };
    });
    const repeated = valids[randomInt(valids.length)]!;
    const signed = rnd(100, 450);
    const sent = rnd(20, signed - 10);
    const tamperedValue = rnd(60, 450);
    const refusals: T3Case[] = [
      { id: "acima_do_teto", label: "", expected: "refuse", req: ok(rnd(501, 1400)), whenAccepted: "mandate" },
      { id: "fornecedor_errado", label: "", expected: "refuse", req: once(() => purchase(m, cred, { valor: rnd(60, 400), fornecedor: SCENARIO.otherSupplierCnpj, now })), whenAccepted: "mandate" },
      { id: "assinatura_adulterada", label: "requisição com a assinatura adulterada", expected: "refuse", req: once(async () => tamperSignature(await ok(rnd(60, 400))())), whenAccepted: "signature" },
      { id: "corpo_alterado", label: `corpo alterado depois de assinado (R$ ${signed} assinado, R$ ${sent} enviado)`, expected: "refuse", req: ok(signed, { sendBody: (b) => ({ ...b, valor: sent }) }), whenAccepted: "signature" },
      { id: "ac_nao_confiavel", label: "credencial de uma AC fora das âncoras", expected: "refuse", req: once(() => purchase(m, untrusted, { valor: rnd(60, 400), fornecedor: SCENARIO.supplierCnpj, now })), whenAccepted: "icp_chain" },
      { id: "chave_errada", label: "requisição assinada por outra chave, não a do agente", expected: "refuse", req: ok(rnd(60, 400), { key: generatePrivateKey() }), whenAccepted: "signature" },
      // Within the signed ceiling, so only the proof (the e-CNPJ signature over the mandate) can catch it.
      { id: "mandato_adulterado", label: `credencial com o teto adulterado para R$ 5.000 (compra de R$ ${tamperedValue})`, expected: "refuse", req: once(async () => tamperMandate(await ok(tamperedValue)())), whenAccepted: "icp_chain" },
      { id: "repeticao", label: `a mesma requisição da ${repeated.label}, repetida`, expected: "refuse", req: () => repeated.req(), whenAccepted: "replay", after: repeated }
    ];
    // Labels that depend on the generated amounts.
    for (const c of refusals) {
      if (c.id === "acima_do_teto" || c.id === "fornecedor_errado") {
        const r = JSON.parse((await c.req()).body) as { valor: number };
        c.label = c.id === "acima_do_teto" ? `compra de R$ ${r.valor} (acima do teto por compra)` : `compra de R$ ${r.valor} de outro fornecedor`;
      }
    }
    const order = shuffle([...valids, ...refusals]);
    // The replay goes to a random position after the purchase it repeats.
    const replay = order.splice(order.findIndex((c) => c.after), 1)[0]!;
    const from = order.indexOf(replay.after!) + 1;
    order.splice(rnd(from, order.length), 0, replay);

    const results: { c: T3Case; call: Call }[] = [];
    for (const c of order) {
      const call = await v.verify(a, await c.req());
      if (call.failure?.notImpl) a.not_implemented = true;
      results.push({ c, call });
    }
    const validResults = results.filter((r) => r.c.expected === "accept");
    const allValid = validResults.every((r) => r.call.accepted && !r.call.failure);
    for (const r of validResults) if (r.call.accepted && !r.call.failure && r.call.ms !== null) a.accept_ms!.push(round(r.call.ms));
    const firstBadValid = validResults.find((r) => !(r.call.accepted && !r.call.failure));
    const subs: SubCase[] = [{ id: "compra_valida", expected: "accept", pass: allValid, category: firstBadValid ? wrongCategory(firstBadValid.call, "other") : null }];
    fb.push("  (os pedidos chegam em ordem aleatória, como num marketplace de verdade)");
    for (const { c, call } of results) {
      let pass: boolean;
      if (c.expected === "accept") pass = call.accepted && !call.failure;
      else {
        // A refusal only counts when the valid purchases were accepted: a verifier that refuses everything scores nothing.
        pass = !call.accepted && !call.failure && allValid;
        subs.push({ id: c.id, expected: "refuse", pass, category: pass ? null : call.accepted || call.failure ? wrongCategory(call, c.whenAccepted) : (subs[0]!.category ?? "other") });
      }
      const hint = pass ? "" : c.expected === "accept" ? " (esperado: aceitar)" : allValid || call.accepted || call.failure ? " (esperado: recusar)" : " (só conta quando as compras válidas forem aceitas)";
      fb.push(`${mark(pass)} ${c.label}: ${describe(call)}${hint}`);
    }
    a.sub_cases = subs;
    for (const s of subs) if (!s.pass && s.category) failWith(a, s.category);
    a.pass = subs.every((s) => s.pass);
    return { attempt: a, feedback: fb };
  } finally {
    v.close();
  }
}

/** A refusal for revocation must carry the library's revocation code in motivo, not just any word. */
const REVOCATION_CODE = /KYA_CERTIFICATE_REVOKED|\bCERTIFICATE_REVOKED\b/;

interface T4Stage {
  id: "antes_da_revogacao" | "lcr_reemitida" | "lcr_outra_revogacao" | "depois_da_revogacao";
  label: string;
  clock: number;
  crl: Uint8Array;
  purchases: number;
  expect: "accept" | "revoked";
}

/**
 * T4. A random number of CRLs, at random clock steps (each past the previous CRL's nextUpdate): the current one;
 * two to four re-issued ones, one of them revoking another certificate (the list grows, the company is still in
 * force); then the CRL that revokes the company's certificate, and one more re-issue of it. One or two purchases
 * per CRL. So "the bytes changed", "the list got longer", "the Nth fetch" or "after some minutes" never pass.
 */
export async function runT4(m: Material): Promise<TaskOutcome> {
  const a = base("t4");
  const fb: string[] = [];
  const t = Date.now();
  const stages: T4Stage[] = [];
  let clock = t;
  const add = async (id: T4Stage["id"], label: string, p: { revokeCompany: boolean; revokeOthers?: string[]; revokedAt?: number }) => {
    const nextUpdate = clock + rnd(10, 240) * MIN;
    const crl = await makeCrl(m.ac, { thisUpdate: new Date(clock - rnd(1, 5) * MIN), nextUpdate: new Date(nextUpdate), revokeCompany: p.revokeCompany, revokeOthers: p.revokeOthers, revokedAt: p.revokedAt === undefined ? undefined : new Date(p.revokedAt) });
    stages.push({ id, label, clock, crl, purchases: rnd(1, 2), expect: id === "depois_da_revogacao" ? "revoked" : "accept" });
    clock = nextUpdate + rnd(1, 120) * MIN;
  };
  const hours = (ms: number) => (ms < 60 * MIN ? `${Math.round(ms / MIN)} min` : `${(ms / (60 * MIN)).toFixed(1).replace(".", ",")} h`);
  await add("antes_da_revogacao", "LCR atual", { revokeCompany: false });
  const reissues = rnd(2, 4);
  const other = randomInt(reissues);
  const otherSerial = `2${randomInt(0x1000, 0xffff).toString(16)}`;
  for (let i = 0; i < reissues; i++) {
    const rel = hours(clock - t);
    // From the re-issue that revokes another certificate on, that one stays listed (a CRL keeps its entries).
    if (i >= other) await add(i === other ? "lcr_outra_revogacao" : "lcr_reemitida", i === other ? `LCR reemitida que revoga outro certificado (não o da empresa), relógio +${rel}` : `LCR reemitida sem revogação nova, relógio +${rel}`, { revokeCompany: false, revokeOthers: [otherSerial] });
    else await add("lcr_reemitida", `LCR reemitida sem revogação nova, relógio +${rel}`, { revokeCompany: false });
  }
  const revokedAt = clock - MIN;
  await add("depois_da_revogacao", `LCR que revoga o certificado da empresa, relógio +${hours(clock - t)}`, { revokeCompany: true, revokeOthers: [otherSerial], revokedAt });
  await add("depois_da_revogacao", `LCR reemitida, ainda com a revogação, relógio +${hours(clock - t)}`, { revokeCompany: true, revokeOthers: [otherSerial], revokedAt });

  const cred = await referenceCredential(m, new Date(t));
  const v = new Verifier(m);
  const cfg = readConfig(m.ws);
  const passed = new Map<T4Stage["id"], boolean>();
  const category = new Map<T4Stage["id"], ErrorCategory>();
  const record = (s: T4Stage, pass: boolean, cat: ErrorCategory | null) => {
    passed.set(s.id, (passed.get(s.id) ?? true) && pass);
    if (!pass && cat && !category.has(s.id)) category.set(s.id, cat);
  };
  try {
    const created = await v.create(t, stages[0]!.crl);
    if (created) {
      if (created.notImpl) a.not_implemented = true;
      failWith(a, created.cat);
      fb.push(created.text);
      return { attempt: a, feedback: fb };
    }
    let blockedBy: ErrorCategory | null = null;
    for (const s of stages) {
      if (blockedBy) {
        record(s, false, blockedBy);
        continue;
      }
      if (s.expect === "revoked" && !cfg.t4_published_at) {
        // The revoked CRL is "published" in the first run that gets this far; the timer starts with that run.
        cfg.t4_published_at = a.ts;
        writeConfig(m.ws, cfg);
      }
      await v.state(s.clock, s.crl);
      for (let i = 0; i < s.purchases && !blockedBy; i++) {
        const valor = rnd(20, 100); // up to 14 purchases: under the daily ceiling even for a verifier that passes spent_today
        const c = await v.verify(a, await purchase(m, cred, { valor, fornecedor: SCENARIO.supplierCnpj, now: new Date(s.clock) }));
        if (c.failure?.notImpl) a.not_implemented = true;
        let pass: boolean;
        let cat: ErrorCategory | null;
        if (s.expect === "accept") {
          pass = c.accepted && !c.failure;
          if (pass && c.ms !== null) a.accept_ms!.push(round(c.ms));
          cat = pass ? null : wrongCategory(c, "other");
        } else {
          pass = !c.accepted && !c.failure && REVOCATION_CODE.test(c.reason);
          cat = pass ? null : c.accepted ? "revocation" : c.failure ? c.failure.cat : categorize(c.reason) === "revocation" ? "revocation" : categorize(c.reason);
        }
        record(s, pass, cat);
        const hint = pass ? "" : s.expect === "accept" ? " (esperado: aceitar)" : c.accepted ? " (esperado: recusar por revogação)" : " (esperado: recusar com o código de erro de revogação da biblioteca em motivo)";
        fb.push(`${mark(pass)} ${s.label}, compra de R$ ${valor}: ${describe(c)}${hint}`);
        if (!pass) blockedBy = cat ?? "other";
      }
    }
    if (blockedBy) fb.push("  as etapas seguintes só rodam quando esta passar.");
  } finally {
    v.close();
  }
  const ids: T4Stage["id"][] = ["antes_da_revogacao", "lcr_reemitida", "lcr_outra_revogacao", "depois_da_revogacao"];
  a.sub_cases = ids.map((id) => ({ id, expected: id === "depois_da_revogacao" ? "refuse" : "accept", pass: passed.get(id) ?? false, category: passed.get(id) ? null : (category.get(id) ?? "other") }));
  a.t4_published_at = cfg.t4_published_at ?? null;
  for (const s of a.sub_cases) if (!s.pass && s.category) failWith(a, s.category);
  a.pass = a.sub_cases.every((s) => s.pass);
  if (a.pass) fb.push(`  (a LCR do certificado é ${CRL_URL})`);
  return { attempt: a, feedback: fb };
}

export const RUNNERS: Record<TaskId, (m: Material) => Promise<TaskOutcome>> = { t1: runT1, t2: runT2, t3: runT3, t4: runT4 };
