/**
 * Child process that runs the participant's code (src/emitir.mjs, src/verificar.mjs), so that a hanging promise or
 * a busy loop can be stopped by the kit (sandbox.ts kills this process on a per-call timeout) and a crash never
 * takes the kit down. Talks to the kit over IPC (structured clone). It is NOT a security sandbox: the participant's
 * code runs with their own permissions, as it would in their project.
 */
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

type Msg =
  | { id: number; op: "issue"; ctx: Record<string, unknown> }
  | { id: number; op: "verifier"; anchors: string[] }
  | { id: number; op: "state"; clock: number | null; crl: Uint8Array }
  | { id: number; op: "verify"; req: { url: string; method: string; headers: Record<string, string>; body: string } };

const ws = process.argv[2] ?? process.cwd();
const state: { clock: number | null; crl: Uint8Array; urls: string[] } = { clock: null, crl: new Uint8Array(), urls: [] };
let verifier: ((r: Request) => Promise<unknown>) | null = null;

const errorInfo = (e: unknown) => {
  const err = (e ?? {}) as { name?: unknown; message?: unknown; code?: unknown; stack?: unknown };
  return {
    name: typeof err.name === "string" ? err.name : "Error",
    message: typeof err.message === "string" ? err.message : String(e),
    code: typeof err.code === "string" ? err.code : null,
    stack: typeof err.stack === "string" ? err.stack.split("\n").slice(0, 12).join("\n") : ""
  };
};

/** A contract problem (wrong export or return shape), told apart from an exception thrown by the participant. */
class Contract extends Error {}

async function load(file: string, fn: string) {
  const mod = (await import(pathToFileURL(join(ws, "src", file)).href)) as Record<string, unknown>;
  if (typeof mod[fn] !== "function") throw new Contract(`src/${file} não exporta a função ${fn}`);
  return mod[fn] as (ctx: unknown) => Promise<unknown>;
}

const plain = (v: unknown) => JSON.parse(JSON.stringify(v ?? null));

async function handle(m: Msg): Promise<Record<string, unknown>> {
  switch (m.op) {
    case "issue": {
      const fn = await load("emitir.mjs", "emitirCredencial");
      const ctx = { ...m.ctx, pfx: new Uint8Array(m.ctx.pfx as Uint8Array), agora: new Date(m.ctx.agora as number) };
      const out = (await fn(ctx)) as { credential?: unknown; proof?: unknown } | null;
      if (!out || typeof out !== "object" || !out.credential || !out.proof) throw new Contract("emitirCredencial deve devolver { credential, proof }");
      return { value: { credential: plain(out.credential), proof: plain(out.proof) } };
    }
    case "verifier": {
      const fn = await load("verificar.mjs", "criarVerificador");
      const v = await fn({
        anchors: [...m.anchors],
        agora: () => new Date(state.clock ?? Date.now()),
        buscarCrl: async (url: unknown) => {
          state.urls.push(String(url));
          return new Uint8Array(state.crl);
        }
      });
      if (typeof v !== "function") throw new Contract("criarVerificador deve devolver uma função async (request) => ({ aceito, motivo })");
      verifier = v as (r: Request) => Promise<unknown>;
      return {};
    }
    case "state":
      state.clock = m.clock;
      state.crl = m.crl;
      return {};
    case "verify": {
      if (!verifier) throw new Contract("verificador não criado");
      const request = new Request(m.req.url, { method: m.req.method, headers: m.req.headers, body: m.req.body });
      state.urls = [];
      const t0 = performance.now();
      const r = (await verifier(request)) as { aceito?: unknown; motivo?: unknown } | null;
      const ms = performance.now() - t0;
      const shapeOk = !!r && typeof r === "object" && typeof r.aceito === "boolean";
      const motivo = r && typeof r === "object" ? (typeof r.motivo === "string" ? r.motivo : r.motivo === undefined || r.motivo === null ? "" : safeJson(r.motivo)) : "";
      return { value: { shapeOk, aceito: shapeOk ? r!.aceito : null, motivo, ms, urls: state.urls } };
    }
  }
}

const safeJson = (v: unknown) => {
  try {
    return JSON.stringify(v).slice(0, 300);
  } catch {
    return String(v);
  }
};

process.on("message", (m: Msg) => {
  handle(m).then(
    (r) => process.send?.({ id: m.id, ok: true, ...r }),
    (e) => process.send?.({ id: m.id, ok: false, contract: e instanceof Contract ? e.message : null, error: errorInfo(e) })
  );
});
// The participant's stray rejections must not kill the runner before it answers.
process.on("unhandledRejection", () => {});
process.send?.({ id: 0, ok: true, ready: true });
