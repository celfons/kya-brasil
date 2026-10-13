/**
 * The signed request of "Sign in with KYA" (SPEC section 14), shared by the issuer so a counterparty can hand
 * in the agent's request as the proof of an act (D-18). Must stay byte-identical to the npm client's
 * requestText (packages/agent-tools/src/auth.ts); request.test.ts pins both to the same vector.
 */

/** Canonical URL for the signature: origin (lowercase host) + path + query, no fragment. */
export function canonicalUrl(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.host.toLowerCase()}${u.pathname}${u.search}`;
}

export function requestText(p: { credentialId: string; method: string; url: string; created: number; expires: number; contentSha256?: string | null }): string {
  return [
    "KYA Brasil: request",
    `credential: ${p.credentialId}`,
    `method: ${p.method.toUpperCase()}`,
    `url: ${canonicalUrl(p.url)}`,
    `created: ${p.created}`,
    `expires: ${p.expires}`,
    `content-sha256: ${p.contentSha256 ?? "-"}`
  ].join("\n");
}

/** The agent's signed request, as the counterparty received it (the KYA-* headers plus method and URL). */
export interface AgentRequestProof {
  method: string;
  url: string;
  created: number;
  expires: number;
  /** KYA-Content-SHA256, when the request had a body. */
  content_sha256?: string;
  /** KYA-Signature. */
  signature: string;
}
