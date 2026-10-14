/**
 * Cloud e-CNPJ (D-28): the certificate lives at an ICP-Brasil PSC (prestador de serviço de confiança) and signs
 * after the holder approves, usually on the phone. Each PSC has its own contract, registration and API details,
 * so this project ships the interface only: whoever has an agreement with a PSC implements CloudSignatureProvider
 * for it and plugs it into the three entry points (this library, `kya-sign --cloud`, the /sign page of a
 * self-hosted issuer). The KYA side (PKCE, single-use state, the CMS, what is signed) is done here.
 *
 * Typical PSC flow (OAuth 2.0 authorization code with PKCE): send the person to authorizationUrl, get a code at
 * the redirect URI, exchange it for a session, read the certificate, sign hashes. Ask the PSC for the narrowest
 * session it offers (one signature, minutes of lifetime).
 */
import { ecnpjSigner, type ECnpjSigner } from "./ecnpj-sign.js";
import { KyaError } from "./types.js";

/** An authorized session at the PSC: the certificate and a way to sign one SHA-256 hash. */
export interface CloudSession {
  /** Signer certificate first, then the chain if the PSC returns it (DER). */
  certificates(): Promise<Uint8Array[]>;
  /**
   * RSA PKCS#1 v1.5 signature over a SHA-256 hash (32 bytes) computed by the caller: what PSC APIs usually
   * call a "raw" or "PKCS1" signature of a hash. Return the signature bytes.
   */
  signHash(sha256: Uint8Array): Promise<Uint8Array>;
  /** Revoke or forget the session at the PSC, when it supports it. */
  close?(): Promise<void>;
}

/** One PSC. Implement it with your own registration (client id/secret, redirect URIs) and the PSC's API. */
export interface CloudSignatureProvider {
  /** Short id used in URLs and on the command line, e.g. "my-psc". Lowercase letters, digits, "-". */
  readonly id: string;
  /** Name shown to the person, e.g. "BirdID", "VIDaaS". */
  readonly name: string;
  /**
   * Where to send the person to log in and approve. Must carry `state` and the PKCE `codeChallenge` (S256) so the
   * code comes back to `redirectUri` bound to this request. `loginHint` may carry a CNPJ/CPF when the PSC accepts it.
   */
  authorizationUrl(p: { redirectUri: string; state: string; codeChallenge: string; loginHint?: string }): string | Promise<string>;
  /** Exchanges the code for a session (server or CLI side: this is where a client secret would be used). */
  exchangeCode(p: { code: string; redirectUri: string; codeVerifier: string }): Promise<CloudSession>;
}

const toArrayBuffer = (u: Uint8Array) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
const b64url = (u: Uint8Array) => {
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/** PKCE (RFC 7636, S256): a random verifier kept by us and the challenge sent to the PSC. */
export async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  return { verifier, challenge };
}

/** A random, single-use OAuth state value. */
export const newState = () => b64url(crypto.getRandomValues(new Uint8Array(24)));

/** Valid provider ids: what can safely go in a URL path or a CLI flag. */
export const isProviderId = (id: string) => /^[a-z0-9][a-z0-9-]{0,31}$/.test(id);

/**
 * An e-CNPJ signer over a PSC session: the CMS is built here, the PSC only signs the SHA-256 of the signed
 * attributes. Same interface as openPfx (A1) and openToken (A3), so everything downstream is unchanged.
 */
export async function cloudSigner(session: CloudSession): Promise<ECnpjSigner> {
  const certificates = await session.certificates();
  if (!certificates.length) throw new KyaError("CERTIFICATE_INVALID", "the cloud provider returned no certificate");
  return ecnpjSigner({
    certificates,
    sign: async (data) => {
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(data)));
      const sig = await session.signHash(hash);
      if (!sig?.length) throw new KyaError("UPSTREAM_ERROR", "the cloud provider returned an empty signature");
      return sig;
    }
  });
}
