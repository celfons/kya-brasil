/**
 * Automatic grading of the four tasks. The participant's modules (src/emitir.mjs, src/verificar.mjs) are imported
 * and called with the test PKI; every result is checked with the library itself. Nothing here touches the network.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
import { assembleCredential, buildMandate, mandateSigningInput, openPfx, verifySelfIssuedCredential } from "@kya-brasil/core";
import { signRequest } from "@kya-brasil/agent-tools";
import { type ErrorCategory, categorize, categorizeSelfIssuedRule, categorizeThrown } from "./errors.js";
import { COMPANY_CNPJ, CRL_URL, TEST_PASSWORD, makeCrl, pemBlocks, type TestPki } from "./pki.js";
import { type PolicyResult, SCENARIO, gradePolicy, referenceMandate } from "./policy.js";
import { type Attempt, type SubCase, type TaskId, paths, readConfig, writeConfig } from "./workspace.js";

const MIN = 60_000;
const DAY = 86_400_000;

export interface TaskOutcome {
  attempt: Attempt;
  /** Lines of PT-BR feedback for the terminal. */
  feedback: string[];
}

interface Material {
  anchors: string[];
  companyPfx: Uint8Array;
  agent: { kind: "evm"; id: `0x${string}`; privateKey: `0x${string}` };
  crlDer: Uint8Array;
  ac: TestPki["ac"];
}

export function loadMaterial(ws: string): Material {
  const p = paths(ws);
  return {
    anchors: pemBlocks(readFileSync(join(p.pki, "anchors.pem"), "utf8")),
    companyPfx: new Uint8Array(readFileSync(join(p.pki, "empresa.pfx"))),
    agent: JSON.parse(readFileSync(join(p.pki, "agente.json"), "utf8")),
    crlDer: new Uint8Array(readFileSync(join(p.pki, "ac.crl"))),
    ac: JSON.parse(readFileSync(p.ac, "utf8"))
  };
}

/** Imports a participant module afresh (a query string defeats the module cache when several checks run in one process). */
async function importParticipant(ws: string, file: string): Promise<Record<string, unknown>> {
  const full = join(paths(ws).src, file);
  if (!existsSync(full)) throw Object.assign(new Error(`src/${file} não encontrado`), { kitMissing: true });
  return (await import(`${pathToFileURL(full).href}?t=${Date.now()}-${Math.random().toString(36).slice(2)}`)) as Record<string, unknown>;
}

const notImplemented = (e: unknown) => /NAO_IMPLEMENTADO/.test(String((e as Error)?.message ?? e));
const short = (e: unknown) => String((e as Error)?.message ?? e).split("\n")[0]!.slice(0, 300);

function base(task: TaskId): Attempt {
  return { ts: new Date().toISOString(), task, pass: false, error_category: null, error_categories: [], verify_ms: [] };
}
function failWith(a: Attempt, cat: ErrorCategory) {
  if (!a.error_categories.includes(cat)) a.error_categories.push(cat);
  a.error_category ??= cat;
}

// ---------------------------------------------------------------- T1

interface T1Result {
  outcome: TaskOutcome;
  credential: { mandate?: Record<string, unknown>; issued_at?: string; expires_at?: string } | null;
}

async function runIssue(ws: string, m: Material, task: TaskId): Promise<T1Result> {
  const a = base(task);
  const fb: string[] = [];
  let out: { credential?: unknown; proof?: unknown } | undefined;
  try {
    const mod = await importParticipant(ws, "emitir.mjs");
    if (typeof mod.emitirCredencial !== "function") throw new Error("src/emitir.mjs não exporta a função emitirCredencial");
    out = (await (mod.emitirCredencial as (ctx: unknown) => Promise<unknown>)({
      pfx: new Uint8Array(m.companyPfx), senha: TEST_PASSWORD, cnpj: COMPANY_CNPJ, agente: { kind: "evm", id: m.agent.id }, anchors: [...m.anchors], agora: new Date()
    })) as typeof out;
  } catch (e) {
    if (notImplemented(e)) a.not_implemented = true;
    failWith(a, categorizeThrown(e));
    fb.push(a.not_implemented ? "emitirCredencial ainda não foi implementada." : `emitirCredencial lançou um erro: ${short(e)}`);
    return { outcome: { attempt: a, feedback: fb }, credential: null };
  }
  if (!out || typeof out !== "object" || !out.credential || !out.proof) {
    failWith(a, "other");
    fb.push("emitirCredencial deve devolver { credential, proof }.");
    return { outcome: { attempt: a, feedback: fb }, credential: null };
  }
  const credential = out.credential as Parameters<typeof verifySelfIssuedCredential>[0]["credential"];
  const t0 = performance.now();
  const r = await verifySelfIssuedCredential({ credential, proof: out.proof as Parameters<typeof verifySelfIssuedCredential>[0]["proof"], anchors: m.anchors, now: new Date() });
  a.verify_ms.push(round(performance.now() - t0));
  for (const c of r.checks.filter((x) => !x.ok)) {
    failWith(a, categorizeSelfIssuedRule(c.rule, c.detail));
    fb.push(`a credencial não verifica (${c.rule}): ${c.detail}`);
  }
  if (r.ok) {
    const agentId = String((credential as { agent?: { id?: unknown } }).agent?.id ?? "").toLowerCase();
    if (agentId !== m.agent.id.toLowerCase()) {
      failWith(a, "other");
      fb.push("a credencial é válida, mas não é do agente de pki/agente.json (use ctx.agente).");
    }
  }
  a.pass = a.error_categories.length === 0;
  if (a.pass && task === "t1") fb.push("credencial emitida e verificada: assinatura, cadeia até as âncoras de teste, mandato e validade conferem.");
  return { outcome: { attempt: a, feedback: fb }, credential: a.pass ? (credential as T1Result["credential"]) : null };
}

export async function runT1(ws: string, m: Material): Promise<TaskOutcome> {
  return (await runIssue(ws, m, "t1")).outcome;
}

// ---------------------------------------------------------------- T2

const DIR_PT: Record<string, string> = { permissive: "mais permissivo", restrictive: "mais restritivo", neutral: "fora do cenário" };
const GRADE_PT: Record<PolicyResult["grade"], string> = { correct: "correta", permissive: "permissiva demais", restrictive: "restritiva demais", invalid: "inválida" };

export async function runT2(ws: string, m: Material): Promise<TaskOutcome> {
  const issued = await runIssue(ws, m, "t2");
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

type Verify = (request: Request) => Promise<{ aceito?: unknown; motivo?: unknown }>;
const URL_PEDIDOS = "https://marketplace.exemplo.invalid/api/pedidos";

/** The kit's own credential, built from the answer key with the test e-CNPJ: T3 and T4 do not depend on T1. */
async function referenceCredential(m: Material, now: Date) {
  const built = await buildMandate({ credential_id: crypto.randomUUID(), agent: { kind: m.agent.kind, id: m.agent.id }, principal: { kind: "company", cnpj: COMPANY_CNPJ }, mandate: referenceMandate(now), ttl_seconds: SCENARIO.validityDays * 86_400, now });
  const { text } = await mandateSigningInput(built);
  const signer = await openPfx(m.companyPfx, TEST_PASSWORD);
  return assembleCredential(built, await signer.sign(text), [], { anchors: m.anchors, now });
}

async function purchase(m: Material, cred: Awaited<ReturnType<typeof referenceCredential>>, p: { valor: number; fornecedor: string; now: Date }) {
  const body = JSON.stringify({ pedido: crypto.randomUUID(), acao: SCENARIO.action, valor: p.valor, moeda: SCENARIO.currency, fornecedor: p.fornecedor });
  const headers = await signRequest({ credentialId: cred.credential.credential_id, key: { kind: "evm", privateKey: m.agent.privateKey }, method: "POST", url: URL_PEDIDOS, body, now: p.now, present: { credential: cred.credential, proof: cred.proof } });
  return () => new Request(URL_PEDIDOS, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });
}

interface Call {
  accepted: boolean;
  reason: string;
  thrown: unknown;
}

async function call(a: Attempt, verify: Verify, request: Request): Promise<Call> {
  const t0 = performance.now();
  try {
    const r = await verify(request);
    a.verify_ms.push(round(performance.now() - t0));
    if (!r || typeof r !== "object" || typeof r.aceito !== "boolean") return { accepted: false, reason: "", thrown: new Error("o verificador deve devolver { aceito: boolean, motivo?: string }") };
    return { accepted: r.aceito, reason: typeof r.motivo === "string" ? r.motivo : r.motivo === undefined ? "" : JSON.stringify(r.motivo), thrown: null };
  } catch (e) {
    a.verify_ms.push(round(performance.now() - t0));
    return { accepted: false, reason: "", thrown: e };
  }
}

async function makeVerifier(ws: string, ctx: unknown): Promise<Verify> {
  const mod = await importParticipant(ws, "verificar.mjs");
  if (typeof mod.criarVerificador !== "function") throw new Error("src/verificar.mjs não exporta a função criarVerificador");
  const v = await (mod.criarVerificador as (c: unknown) => Promise<unknown>)(ctx);
  if (typeof v !== "function") throw new Error("criarVerificador deve devolver uma função async (request) => ({ aceito, motivo })");
  return v as Verify;
}

/** Category of a wrong answer: what the participant's refusal says, or what the case was about when wrongly accepted. */
function wrongCategory(c: Call, whenAccepted: ErrorCategory): ErrorCategory {
  if (c.thrown) return categorizeThrown(c.thrown);
  if (c.accepted) return whenAccepted;
  return categorize(c.reason);
}

const describe = (c: Call) => (c.thrown ? `erro: ${short(c.thrown)}` : c.accepted ? "aceito" : `recusado${c.reason ? ` (${c.reason.slice(0, 120)})` : ""}`);

export async function runT3(ws: string, m: Material): Promise<TaskOutcome> {
  const a = base("t3");
  const fb: string[] = [];
  const now = new Date();
  const cred = await referenceCredential(m, now);
  let verify: Verify;
  try {
    verify = await makeVerifier(ws, { anchors: [...m.anchors], agora: () => new Date(), buscarCrl: async (_url: string) => new Uint8Array(m.crlDer) });
  } catch (e) {
    if (notImplemented(e)) a.not_implemented = true;
    failWith(a, categorizeThrown(e));
    fb.push(a.not_implemented ? "criarVerificador ainda não foi implementada." : `criarVerificador lançou um erro: ${short(e)}`);
    return { attempt: a, feedback: fb };
  }
  const valid = await purchase(m, cred, { valor: 120, fornecedor: SCENARIO.supplierCnpj, now });
  const tooMuch = await purchase(m, cred, { valor: 800, fornecedor: SCENARIO.supplierCnpj, now });
  const otherSupplier = await purchase(m, cred, { valor: 100, fornecedor: SCENARIO.otherSupplierCnpj, now });

  const subs: SubCase[] = [];
  const first = await call(a, verify, valid());
  if (first.thrown && notImplemented(first.thrown)) a.not_implemented = true;
  const okFirst = first.accepted && !first.thrown;
  subs.push({ id: "compra_valida", expected: "accept", pass: okFirst, category: okFirst ? null : wrongCategory(first, "other") });
  fb.push(`${mark(okFirst)} compra de R$ 120 do fornecedor X: ${describe(first)}${okFirst ? "" : " (esperado: aceitar)"}`);

  const cases: [string, string, () => Request, ErrorCategory][] = [
    ["acima_do_teto", "compra de R$ 800 (acima do teto por compra)", tooMuch, "mandate"],
    ["fornecedor_errado", "compra de R$ 100 de outro fornecedor", otherSupplier, "mandate"],
    ["repeticao", "a mesma requisição da compra de R$ 120, repetida", valid, "replay"]
  ];
  for (const [id, label, req, whenAccepted] of cases) {
    const c = await call(a, verify, req());
    // A refusal only counts when the valid purchase was accepted: a verifier that refuses everything scores nothing.
    const pass = !c.accepted && !c.thrown && okFirst;
    subs.push({ id, expected: "refuse", pass, category: pass ? null : c.accepted || c.thrown ? wrongCategory(c, whenAccepted) : (subs[0]!.category ?? "other") });
    fb.push(`${mark(pass)} ${label}: ${describe(c)}${pass ? "" : okFirst ? " (esperado: recusar)" : " (só conta depois que a compra válida for aceita)"}`);
  }
  a.sub_cases = subs;
  for (const s of subs) if (!s.pass && s.category) failWith(a, s.category);
  a.pass = subs.every((s) => s.pass);
  return { attempt: a, feedback: fb };
}

export async function runT4(ws: string, m: Material): Promise<TaskOutcome> {
  const a = base("t4");
  const fb: string[] = [];
  const t = Date.now();
  const clock = { t };
  const crlBefore = await makeCrl(m.ac, { thisUpdate: new Date(t - MIN), nextUpdate: new Date(t + 10 * MIN), revokeCompany: false });
  const crlAfter = await makeCrl(m.ac, { thisUpdate: new Date(t - MIN / 2), nextUpdate: new Date(t + 7 * DAY), revokeCompany: true, revokedAt: new Date(t - MIN / 2) });
  let published = crlBefore;
  const urls = new Set<string>();
  const cred = await referenceCredential(m, new Date(t));
  let verify: Verify;
  try {
    verify = await makeVerifier(ws, {
      anchors: [...m.anchors],
      agora: () => new Date(clock.t),
      buscarCrl: async (url: string) => {
        urls.add(String(url));
        return new Uint8Array(published);
      }
    });
  } catch (e) {
    if (notImplemented(e)) a.not_implemented = true;
    failWith(a, categorizeThrown(e));
    fb.push(a.not_implemented ? "criarVerificador ainda não foi implementada." : `criarVerificador lançou um erro: ${short(e)}`);
    return { attempt: a, feedback: fb };
  }
  const before = await purchase(m, cred, { valor: 100, fornecedor: SCENARIO.supplierCnpj, now: new Date(clock.t) });
  const c1 = await call(a, verify, before());
  if (c1.thrown && notImplemented(c1.thrown)) a.not_implemented = true;
  const ok1 = c1.accepted && !c1.thrown;
  const subs: SubCase[] = [{ id: "antes_da_revogacao", expected: "accept", pass: ok1, category: ok1 ? null : wrongCategory(c1, "other") }];
  fb.push(`${mark(ok1)} antes da revogação, compra de R$ 100: ${describe(c1)}${ok1 ? "" : " (esperado: aceitar)"}`);

  const cfg = readConfig(ws);
  if (ok1) {
    // The revoked CRL is "published" once the verifier works before revocation; the clock moves past the old nextUpdate.
    if (!cfg.t4_published_at) {
      cfg.t4_published_at = new Date().toISOString();
      writeConfig(ws, cfg);
    }
    published = crlAfter;
    clock.t = t + 15 * MIN;
    const after = await purchase(m, cred, { valor: 100, fornecedor: SCENARIO.supplierCnpj, now: new Date(clock.t) });
    const c2 = await call(a, verify, after());
    const reason = c2.thrown || c2.accepted ? null : categorize(c2.reason);
    const ok2 = reason === "revocation";
    subs.push({ id: "depois_da_revogacao", expected: "refuse", pass: ok2, category: ok2 ? null : c2.accepted ? "revocation" : c2.thrown ? categorizeThrown(c2.thrown) : (reason ?? "other") });
    fb.push(`${mark(ok2)} LCR nova publicada (certificado revogado), relógio +15 min, compra de R$ 100: ${describe(c2)}${ok2 ? "" : c2.accepted ? " (esperado: recusar por revogação)" : " (esperado: recusar com o código de erro de revogação em motivo)"}`);
  } else {
    subs.push({ id: "depois_da_revogacao", expected: "refuse", pass: false, category: subs[0]!.category });
    fb.push("  a LCR revogada só é publicada depois que a compra anterior à revogação for aceita.");
  }
  if (urls.size && ![...urls].includes(CRL_URL)) fb.push(`  aviso: buscarCrl foi chamada com ${[...urls][0]}, a LCR do certificado é ${CRL_URL}.`);
  a.sub_cases = subs;
  a.t4_published_at = cfg.t4_published_at ?? null;
  for (const s of subs) if (!s.pass && s.category) failWith(a, s.category);
  a.pass = subs.every((s) => s.pass);
  return { attempt: a, feedback: fb };
}

const mark = (ok: boolean) => (ok ? "  [ok]" : "  [x] ");
const round = (ms: number) => Math.round(ms * 100) / 100;

export const RUNNERS: Record<TaskId, (ws: string, m: Material) => Promise<TaskOutcome>> = { t1: runT1, t2: runT2, t3: runT3, t4: runT4 };
