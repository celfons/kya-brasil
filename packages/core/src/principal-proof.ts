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
import { normalizeCnpj } from "./cnpj.js";
import { type Credential, KyaError, REPRESENTATIVE_METHOD, isPersonPrincipal } from "./types.js";

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

/** The verifier's source of who represents a company: the CPFs of its legal representatives (digits only or formatted). */
export type Representatives = (cnpj: string) => Promise<string[]> | string[];

export interface PrincipalProofCheck {
  rule: "signature" | "certificate" | "agent" | "principal" | "issuer" | "mandate" | "representative";
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

interface Signer {
  certificate_sha256: string | null;
  /** The signer's CPF when an e-CPF signed: compared by the caller and dropped, never returned nor stored. */
  cpf: string | null;
  revocation: PrincipalProofResult["revocation"];
  error: string | null;
}

/** Verifies the CMS over the text with the kind of certificate the credential calls for. Never throws. */
async function signerOf(c: Pick<Credential, "principal">, proof: PrincipalProof, anchors: string[], now: Date, byPerson: boolean): Promise<Signer> {
  try {
    const icp = byPerson
      ? await verifyIcpPersonSignature({ cmsBase64: proof.cms, challenge: proof.text, anchors, now })
      : await verifyIcpSignature({ cmsBase64: proof.cms, challenge: proof.text, expectedCnpj: (c.principal as { cnpj: string }).cnpj, anchors, now });
    const revocation = { serial_number: icp.serial_number, issuer_certificate: icp.issuer_certificate, crl_urls: icp.crl_urls };
    return { certificate_sha256: icp.certificate_sha256, cpf: "cpf" in icp ? icp.cpf : null, revocation, error: null };
  } catch (e) {
    return { certificate_sha256: null, cpf: null, revocation: null, error: e instanceof KyaError ? e.message : `signature does not verify: ${(e as Error).message}` };
  }
}

/**
 * D-43: the e-CPF says who signed, not whom that person represents. Only the verifier's own list can say that the
 * signer may bind this company: with no list, a representative's credential is refused, never accepted on trust.
 */
async function representativeCheck(cnpj: string, signerCpf: string | null, representatives: Representatives | undefined): Promise<{ ok: boolean; detail: string }> {
  if (typeof representatives !== "function") {
    return { ok: false, detail: "a company credential signed by a legal representative needs the verifier's list of representatives (representatives(cnpj)); none was given" };
  }
  if (signerCpf === null) return { ok: false, detail: "the signer could not be identified" };
  try {
    const listed = (await representatives(cnpj)).map((x) => String(x).replace(/\D/g, "")).includes(signerCpf);
    return { ok: listed, detail: listed ? `the signer is a legal representative of CNPJ ${cnpj} in the verifier's list` : `the signer is not a legal representative of CNPJ ${cnpj} in the verifier's list` };
  } catch (e) {
    return { ok: false, detail: `the list of representatives is unavailable: ${(e as Error).message}` };
  }
}

/**
 * Checks, against the credential and without the issuer, that the principal's own signature authorizes this
 * agent with this mandate: the CMS verifies over the text up to the ICP-Brasil anchors; the certificate is the
 * one the credential records; the text names the credential's agent, principal and issuer; and the mandate hash
 * in the text equals the hash of the credential's mandate. `anchors`, `now` and the revocation check are the
 * caller's. Never throws on a bad proof: every check is reported.
 */
export async function verifyPrincipalProof(p: { credential: Pick<Credential, "agent" | "principal" | "authorized_by" | "mandate" | "issuer">; proof: PrincipalProof; anchors: string[]; now: Date; representatives?: Representatives }): Promise<PrincipalProofResult> {
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
  // D-43: a company credential signed by a legal representative's e-CPF alone, with no e-CNPJ.
  const representative = !person && c.authorized_by?.method === REPRESENTATIVE_METHOD;
  const signer = await signerOf(c, proof, p.anchors, p.now, person || representative);
  const certificateSha256 = signer.certificate_sha256;
  const revocation = signer.revocation;
  push("signature", signer.error === null, signer.error ?? `${person || representative ? "e-CPF" : "e-CNPJ"} signature over the text verifies up to the ICP-Brasil anchors`);

  if (representative) {
    const r = await representativeCheck(normalizeCnpj((c.principal as { cnpj: string }).cnpj), signer.cpf, p.representatives);
    push("representative", r.ok, r.detail);
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
  const actual = await mandateSha256(c.mandate).catch(() => null); // not JSON data (RFC 8785): commits to nothing
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
