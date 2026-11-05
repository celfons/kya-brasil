// TEST FIXTURE ONLY (from the second QA): a verifier that must NOT pass; see src/regressions.test.ts.
// No cryptography: passes T3 (accept first only) and T4 (accept 2, then refuse as revoked) by counting calls.
// T3 and T4 call criarVerificador separately; tell them apart by the request body.
export async function criarVerificador(ctx) {
  let n = 0; let t4 = null;
  return async (request) => {
    const b = JSON.parse(await request.clone().text());
    if (t4 === null) t4 = b.valor === 100;
    n++;
    if (!t4) return n === 1 ? { aceito: true } : { aceito: false, motivo: "KYA_BAD_SIGNATURE" };
    return n <= 2 ? { aceito: true } : { aceito: false, motivo: "KYA_CERTIFICATE_REVOKED" };
  };
}
