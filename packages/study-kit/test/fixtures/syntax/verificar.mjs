// TEST FIXTURE: a syntax error on line 3.
export async function criarVerificador() {
  return async () => ({ aceito: true, };
}
