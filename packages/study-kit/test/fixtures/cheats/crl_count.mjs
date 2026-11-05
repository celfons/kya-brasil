// TEST FIXTURE ONLY (from the second QA): a verifier that must NOT pass; see src/regressions.test.ts.
import { createKyaAuth, memoryReplayCache } from "@kya-brasil/agent-tools";
import { evidenceFromRevocation, verifyCrl } from "@kya-brasil/core";
export async function criarVerificador(ctx) {
  const now = () => ctx.agora();
  const state = { first: null, firstLen: null, n: 0, cached: null, t0: ctx.agora().getTime() };
  async function certificateStatus({ revocation }) {
    const url = revocation.crl_urls[0];
    const at = now();
    const crlDer = await ctx.buscarCrl(url); const crl = await verifyCrl({ crlDer, issuerCertificate: revocation.issuer_certificate, pastNextUpdate: "accept", now: at }); const s = crl.lookup(revocation.serial_number); state.n++; const rv = state.n >= 3; return evidenceFromRevocation({ ...s, revoked: rv, revoked_at: rv ? at.toISOString() : null, reason: rv ? "keyCompromise" : null }, url);
  }
  const auth = createKyaAuth({ replayCache: memoryReplayCache(), offline: { anchors: ctx.anchors, now, certificateStatus } });
  return async (request) => {
    const copy = request.clone();
    const r = await auth.authenticate(request);
    if (!r.ok) return { aceito: false, motivo: r.error };
    const body = JSON.parse(await copy.text());
    const v = r.kya.check({ action: body.acao, amount: body.valor, currency: body.moeda, counterparty: body.fornecedor });
    if (!v.allowed) return { aceito: false, motivo: v.checks.filter((c) => !c.ok).map((c) => c.rule).join(",") };
    return { aceito: true };
  };
}
