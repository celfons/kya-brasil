// TEST FIXTURE ONLY (from the second QA): a verifier that must NOT pass; see src/regressions.test.ts.
// No cryptography at all: accept the first request of each verifier, refuse the rest.
export async function criarVerificador(ctx) {
  let n = 0;
  return async (request) => (n++ === 0 ? { aceito: true } : { aceito: false, motivo: "nope" });
}
