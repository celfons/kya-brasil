// TEST FIXTURE ONLY (from the second QA): a verifier that must NOT pass; see src/regressions.test.ts.
// No cryptography at all.
export async function criarVerificador(ctx) {
  let n = 0;
  return async (request) => (n++ < 2 ? { aceito: true } : { aceito: false, motivo: "revoked" });
}
