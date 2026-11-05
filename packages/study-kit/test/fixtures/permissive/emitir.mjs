// Reference solution (TEST FIXTURE ONLY, never shipped to participants): T1 passes, but the mandate is too permissive: higher ceiling, any counterparty, delegation, 90 days.
import { assembleCredential, buildMandate, mandateSigningInput, openPfx } from "@kya-brasil/core";

export async function emitirCredencial(ctx) {
  const now = ctx.agora;
  const built = await buildMandate({
    credential_id: crypto.randomUUID(),
    agent: ctx.agente,
    principal: { kind: "company", cnpj: ctx.cnpj },
    mandate: {
      actions: ["buy"],
      max_per_operation: { amount: 1000, currency: "BRL" },
      max_per_day: { amount: 1500, currency: "BRL" },
      currencies: ["BRL"],
      counterparties: [],
      payment_instruments: [],
      valid_from: now.toISOString(),
      valid_until: new Date(now.getTime() + 90 * 86_400_000).toISOString(),
      delegation: { max_depth: 1, max_ttl_seconds: 3600 }
    },
    ttl_seconds: 90 * 86_400,
    now
  });
  const { text } = await mandateSigningInput(built);
  const company = await openPfx(ctx.pfx, ctx.senha);
  return assembleCredential(built, await company.sign(text), [], { anchors: ctx.anchors, now });
}
