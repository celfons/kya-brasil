// TEST FIXTURE ONLY (from the third QA round): a verifier that must NOT pass T4; see src/regressions.test.ts.
import { createKyaAuth, memoryReplayCache } from "@kya-brasil/agent-tools";
import { evidenceFromRevocation, verifyCrl } from "@kya-brasil/core";
import { X509Crl } from "@peculiar/x509";
export async function criarVerificador(ctx) {
  const now = () => ctx.agora();
  const state = { first: null, n: 0, seenUrls: new Set(), lastHex: null, distinct: 0, everRevoked: false };
  async function certificateStatus({ revocation }) {
    const url = revocation.crl_urls[0];
    const at = now();
    const crlDer = await ctx.buscarCrl(url); const crl = await verifyCrl({ crlDer, issuerCertificate: revocation.issuer_certificate, pastNextUpdate: "refuse", now: at }); const s = crl.lookup(revocation.serial_number); const entries = new X509Crl(crlDer).entries.length; if (state.first === null) state.first = entries; const rv = entries >= state.first + 2; return evidenceFromRevocation({ ...s, revoked: rv, revoked_at: rv ? at.toISOString() : null, reason: rv ? "keyCompromise" : null }, url);
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
