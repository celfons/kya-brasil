// Reference solution (TEST FIXTURE ONLY, never shipped to participants): T1 and T2 done right.
import { assembleCredential, buildMandate, mandateSigningInput, openPfx } from "@kya-brasil/core";

export async function emitirCredencial(ctx) {
  const now = ctx.agora;
  const built = await buildMandate({
    credential_id: crypto.randomUUID(),
    agent: ctx.agente,
    principal: { kind: "company", cnpj: ctx.cnpj },
    mandate: {
      actions: ["buy"],
      max_per_operation: { amount: 500, currency: "BRL" },
      max_per_day: { amount: 1500, currency: "BRL" },
      currencies: ["BRL"],
      counterparties: ["98.765.432/0001-98"],
      payment_instruments: [],
      valid_from: now.toISOString(),
      valid_until: new Date(now.getTime() + 30 * 86_400_000).toISOString(),
      delegation: null
    },
    ttl_seconds: 30 * 86_400,
    now
  });
  const { text } = await mandateSigningInput(built);
  const company = await openPfx(ctx.pfx, ctx.senha);
  return assembleCredential(built, await company.sign(text), [], { anchors: ctx.anchors, now });
}
