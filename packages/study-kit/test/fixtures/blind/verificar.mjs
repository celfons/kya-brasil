// Crypto-blind verifier (TEST FIXTURE ONLY): reads the JSON body, compares amount and supplier, remembers request
// signatures in a Set, and calls the certificate "revoked" whenever the CRL bytes change. Checks no signature,
// chain or proof: the kit must not let it pass T3 or T4.
export async function criarVerificador(ctx) {
  const seen = new Set();
  let firstCrl = null;
  return async (request) => {
    const pedido = await request.clone().json();
    const sig = request.headers.get("kya-signature");
    if (seen.has(sig)) return { aceito: false, motivo: "KYA_REQUEST_REPLAYED" };
    seen.add(sig);
    const crl = Buffer.from(await ctx.buscarCrl("x")).toString("base64");
    firstCrl ??= crl;
    if (crl !== firstCrl) return { aceito: false, motivo: "KYA_CERTIFICATE_REVOKED" };
    if (pedido.valor > 500) return { aceito: false, motivo: "max_per_operation" };
    if (pedido.fornecedor !== "98765432000198") return { aceito: false, motivo: "counterparties" };
    return { aceito: true };
  };
}
