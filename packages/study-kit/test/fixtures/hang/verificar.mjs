// TEST FIXTURE: a verifier whose answer never comes.
export async function criarVerificador() {
  return () => new Promise(() => {});
}
