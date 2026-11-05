// TEST FIXTURE: the right idea, the wrong return shape.
export async function criarVerificador() {
  return async () => ({ ok: true });
}
