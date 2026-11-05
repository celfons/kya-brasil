// Reference solution (TEST FIXTURE ONLY, never shipped to participants): T3 and T4 done right.
import { createKyaAuth, memoryReplayCache } from "@kya-brasil/agent-tools";
import { evidenceFromRevocation, verifyCrl } from "@kya-brasil/core";

export async function criarVerificador(ctx) {
  const cache = new Map(); // CRL by URL, until its nextUpdate
  const auth = createKyaAuth({
    replayCache: memoryReplayCache(),
    offline: {
      anchors: ctx.anchors,
      now: ctx.agora,
      certificateStatus: async ({ revocation }) => {
        const url = revocation.crl_urls[0];
        const now = ctx.agora();
        let crl = cache.get(url);
        if (!crl || (crl.next_update && Date.parse(crl.next_update) <= now.getTime())) {
          crl = await verifyCrl({ crlDer: await ctx.buscarCrl(url), issuerCertificate: revocation.issuer_certificate, pastNextUpdate: "refuse", now });
          cache.set(url, crl);
        }
        return evidenceFromRevocation(crl.lookup(revocation.serial_number), url);
      }
    }
  });
  return async (request) => {
    const pedido = await request.clone().json();
    const r = await auth.authenticate(request);
    if (!r.ok) return { aceito: false, motivo: r.error };
    const v = r.kya.check({ action: pedido.acao, amount: pedido.valor, currency: pedido.moeda, counterparty: pedido.fornecedor });
    return v.allowed ? { aceito: true } : { aceito: false, motivo: v.checks.filter((c) => !c.ok).map((c) => c.rule).join(", ") };
  };
}
