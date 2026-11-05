// Naive verifier (TEST FIXTURE ONLY): no replay cache, and the CRL is read once and kept forever.
import { createKyaAuth } from "@kya-brasil/agent-tools";
import { evidenceFromRevocation, verifyCrl } from "@kya-brasil/core";

export async function criarVerificador(ctx) {
  let crl = null;
  const auth = createKyaAuth({
    offline: {
      anchors: ctx.anchors,
      now: ctx.agora,
      certificateStatus: async ({ revocation }) => {
        crl ??= await verifyCrl({ crlDer: await ctx.buscarCrl(revocation.crl_urls[0]), issuerCertificate: revocation.issuer_certificate, pastNextUpdate: "accept" });
        return evidenceFromRevocation(crl.lookup(revocation.serial_number));
      }
    }
  });
  return async (request) => {
    const pedido = await request.clone().json();
    const r = await auth.authenticate(request);
    if (!r.ok) return { aceito: false, motivo: r.error };
    const v = r.kya.check({ action: pedido.acao, amount: pedido.valor, currency: pedido.moeda, counterparty: pedido.fornecedor });
    return { aceito: v.allowed, motivo: v.checks.filter((c) => !c.ok).map((c) => c.rule).join(", ") };
  };
}
