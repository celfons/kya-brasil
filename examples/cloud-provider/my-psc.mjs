// Template: a CloudSignatureProvider for your PSC (cloud e-CNPJ). Not implemented on purpose: each PSC has its own
// contract, registration (client id, secret, redirect URIs), endpoints and parameters. Fill in the three methods
// from your PSC's documentation, then use this file with:
//   - the library:  cloudSigner(await provider.exchangeCode(...))           (@kya-brasil/core)
//   - the terminal: kya-sign --cloud ./my-psc.mjs --link "<sign_url>"       (@kya-brasil/agent-tools)
//   - the /sign page of your own issuer: return it from apps/worker/src/cloud-providers.ts
// Ask the PSC for the narrowest authorization it offers: one signature, a few minutes of lifetime.

/** @type {import("@kya-brasil/core").CloudSignatureProvider} */
export const provider = {
  id: "my-psc", // lowercase letters, digits, "-": used in URLs and on the command line
  name: "Meu PSC", // shown to the person

  /**
   * The PSC's authorization URL: the person logs in and approves (often on the phone app).
   * Include: your client id, redirectUri, state, codeChallenge with method S256, the scope for signing and,
   * if the PSC supports it, a one-signature / short lifetime request. loginHint may carry a CNPJ or CPF.
   */
  authorizationUrl({ redirectUri, state, codeChallenge, loginHint }) {
    throw new Error("not implemented: build your PSC's authorization URL");
  },

  /**
   * Exchange the code for an access token at the PSC's token endpoint (with codeVerifier, and your client
   * secret if the PSC requires one; keep it in an environment variable, never in the code), then return a
   * session with:
   *   certificates(): the e-CNPJ certificate (DER bytes), signer first, chain after if the PSC returns it;
   *   signHash(sha256): the PSC's signature of that 32-byte SHA-256 hash, RSA PKCS#1 v1.5 ("raw"/"PKCS1"
   *     signature of a hash, not a CMS), as bytes;
   *   close(): optional, revoke the token if the PSC allows.
   */
  async exchangeCode({ code, redirectUri, codeVerifier }) {
    throw new Error("not implemented: exchange the code and return { certificates, signHash, close }");
  }
};

export default provider;
