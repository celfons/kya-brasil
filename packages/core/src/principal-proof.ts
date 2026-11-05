/**
 * Verification without trusting the issuer (D-34, SPEC section 19).
 *
 * Since D-33 the principal signs, with the e-CNPJ or e-CPF, a challenge that names the agent and carries the
 * mandate's SHA-256, and keeps the signed text and the detached CMS (.p7s). When the principal chooses to hand
 * them to its agent, the agent can present them with a request, and any verifier can check by itself, with the
 * ICP-Brasil trust anchors, that this principal authorized this agent with these powers: the issuer's key is
 * then needed for nothing but the credential's status.
 *
 * Pure functions, no network. The certificate's revocation is the caller's: this module returns what is needed
 * to fetch and check the CRL (checkRevocation, evidenceFromRevocation), never personal data. The CMS carries the
 * signer's certificate, so the principal decides when to share it, and the verifier treats it as personal data.
 */
import { base64url, mandateSha256OfChallenge } from "./challenge.js";
import { mandateSha256 } from "./credential.js";
import { verifyIcpPersonSignature, verifyIcpSignature } from "./icp-brasil.js";
import { type Credential, KyaError, isPersonPrincipal } from "./types.js";

/** What the agent presents: the exact challenge text the principal signed, and the detached CMS (base64 DER). */
export interface PrincipalProof {
  text: string;
  cms: string;
  /**
   * Co-signatures by legal representatives (SPEC section 21): CMS by e-CPF over the same `text`. Optional, additive.
   * They carry the representatives' certificates (and so their CPF): presented to the verifier, never stored in the
   * credential.
   */
  cosignatures?: string[];
}

export interface PrincipalProofCheck {
  rule: "signature" | "certificate" | "agent" | "principal" | "issuer" | "mandate";
  ok: boolean;
  detail: string;
}

export interface PrincipalProofResult {
  ok: boolean;
  checks: PrincipalProofCheck[];
  /** For the caller's revocation check of the signing certificate; null when the signature did not verify. */
  revocation: { serial_number: string; issuer_certificate: string | null; crl_urls: string[] } | null;
}

const lineOf = (text: string, key: string): string | null => {
  const lines = text.split("\n").filter((l) => l.startsWith(`${key}: `));
  return lines.length === 1 ? lines[0]!.slice(key.length + 2) : null;
};

/**
 * Checks, against the credential and without the issuer, that the principal's own signature authorizes this
 * agent with this mandate: the CMS verifies over the text up to the ICP-Brasil anchors; the certificate is the
 * one the credential records; the text names the credential's agent, principal and issuer; and the mandate hash
 * in the text equals the hash of the credential's mandate. `anchors`, `now` and the revocation check are the
 * caller's. Never throws on a bad proof: every check is reported.
 */
export async function verifyPrincipalProof(p: { credential: Pick<Credential, "agent" | "principal" | "authorized_by" | "mandate" | "issuer">; proof: PrincipalProof; anchors: string[]; now: Date }): Promise<PrincipalProofResult> {
  const { credential: c, proof } = p;
  const checks: PrincipalProofCheck[] = [];
  const push = (rule: PrincipalProofCheck["rule"], ok: boolean, detail: string) => checks.push({ rule, ok, detail });
  if (!proof || typeof proof.text !== "string" || typeof proof.cms !== "string") {
    push("signature", false, "proof must carry the signed text and the CMS");
    return { ok: false, checks, revocation: null };
  }
  if (!(p.now instanceof Date) || Number.isNaN(p.now.getTime())) {
    push("signature", false, "the verifier's clock is not a valid date");
    return { ok: false, checks, revocation: null };
  }

  const person = isPersonPrincipal(c.principal);
  let certificateSha256: string | null = null;
  let revocation: PrincipalProofResult["revocation"] = null;
  try {
    const icp = person
      ? await verifyIcpPersonSignature({ cmsBase64: proof.cms, challenge: proof.text, anchors: p.anchors, now: p.now })
      : await verifyIcpSignature({ cmsBase64: proof.cms, challenge: proof.text, expectedCnpj: (c.principal as { cnpj: string }).cnpj, anchors: p.anchors, now: p.now });
    certificateSha256 = icp.certificate_sha256;
    revocation = { serial_number: icp.serial_number, issuer_certificate: icp.issuer_certificate, crl_urls: icp.crl_urls };
    push("signature", true, `${person ? "e-CPF" : "e-CNPJ"} signature over the text verifies up to the ICP-Brasil anchors`);
  } catch (e) {
    push("signature", false, e instanceof KyaError ? e.message : `signature does not verify: ${(e as Error).message}`);
  }

  if (certificateSha256 !== null) {
    const same = certificateSha256 === c.authorized_by.certificate_sha256;
    push("certificate", same, same ? "signed with the certificate the credential records" : "signed with another certificate than the one the credential records");
  }

  const agent = lineOf(proof.text, "agent");
  const expectedAgent = `${c.agent.kind}:${c.agent.id}`;
  push("agent", agent === expectedAgent, agent === expectedAgent ? `text names the credential's agent ${expectedAgent}` : `text names agent ${agent ?? "(none)"}, the credential ${expectedAgent}`);

  if (person) {
    const ok = lineOf(proof.text, "principal") === "person (e-CPF)";
    push("principal", ok, ok ? "text is a natural person's authorization" : "text is not a natural person's authorization");
  } else {
    const cnpj = lineOf(proof.text, "cnpj");
    const expected = (c.principal as { cnpj: string }).cnpj;
    push("principal", cnpj === expected, cnpj === expected ? `text names CNPJ ${expected}` : `text names CNPJ ${cnpj ?? "(none)"}, the credential ${expected}`);
  }

  const issuer = lineOf(proof.text, "issuer");
  push("issuer", issuer === c.issuer, issuer === c.issuer ? `text names issuer ${c.issuer}` : `text names issuer ${issuer ?? "(none)"}, the credential ${c.issuer}`);

  const signed = mandateSha256OfChallenge(proof.text);
  const actual = await mandateSha256(c.mandate);
  const recorded = c.authorized_by.mandate_sha256;
  const mandateOk = signed !== null && signed === actual && (!recorded || recorded === signed);
  push("mandate", mandateOk, signed === null ? "text carries no mandate hash (signed before D-33)" : mandateOk ? "text commits to the credential's mandate" : "text commits to another mandate than the credential's");

  return { ok: checks.every((x) => x.ok), checks, revocation };
}

/** Header value for a request: base64url of the JSON { text, cms }. */
export function encodePrincipalProofHeader(proof: PrincipalProof): string {
  return base64url.encode(new TextEncoder().encode(JSON.stringify(proof.cosignatures?.length ? { text: proof.text, cms: proof.cms, cosignatures: proof.cosignatures } : { text: proof.text, cms: proof.cms })));
}

/** Parses the header value; throws INVALID_INPUT when it is not a proof. */
export function decodePrincipalProofHeader(value: string): PrincipalProof {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(base64url.decode(value.trim())));
  } catch {
    throw new KyaError("INVALID_INPUT", "KYA-Principal-Proof is not base64url JSON");
  }
  const o = parsed as Record<string, unknown> | null;
  if (!o || typeof o.text !== "string" || typeof o.cms !== "string") throw new KyaError("INVALID_INPUT", "KYA-Principal-Proof must carry text and cms");
  if (o.cosignatures === undefined) return { text: o.text, cms: o.cms };
  if (!Array.isArray(o.cosignatures) || !o.cosignatures.every((c) => typeof c === "string")) throw new KyaError("INVALID_INPUT", "KYA-Principal-Proof cosignatures must be a list of base64 CMS");
  return { text: o.text, cms: o.cms, cosignatures: o.cosignatures as string[] };
}
