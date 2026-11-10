/**
 * Co-signature by a legal representative (SPEC section 21). Whoever holds a company's e-CNPJ can sign a mandate,
 * whether or not they represent the company (shown by the Alloy model). A self-issued company credential may
 * therefore carry co-signatures: CMS signatures by e-CPF over the SAME text the e-CNPJ signed
 * (mandateSigningInput). The verifier supplies who represents the company (the QSA, from its own source): the core
 * never calls the Receita Federal.
 *
 * Privacy (SPEC section 12): the credential keeps only, per co-signature, the e-CPF certificate's hash, issuer and
 * dates. The CMS (which carries the certificate, and so the CPF and name) travels in the proof the agent presents,
 * as the principal's own CMS does (section 19); the CPF is read from it at verification and never returned.
 *
 * Pure: no network, no storage, the clock is the caller's.
 */
import { normalizeCnpj } from "./cnpj.js";
import { ecnpjResponsibleCpf, verifyIcpPersonSignature } from "./icp-brasil.js";
import { type IssuedCredential, SELF_ISSUER, verifySelfIssuedCredential, withCertificates } from "./issuance.js";
import { type Cosignature, KyaError, REPRESENTATIVE_METHOD, isPersonPrincipal } from "./types.js";

const bad = (why: string) => new KyaError("INVALID_INPUT", why);
const validDate = (d: unknown): d is Date => d instanceof Date && !Number.isNaN(d.getTime());

/**
 * Adds a legal representative's co-signature to a self-issued company credential: `cms` is a CMS by an e-CPF over
 * `issued.proof.text` (the same bytes the e-CNPJ signed), `certChain` the chain to add when the CMS lacks it.
 * Verifies the signature, the certificate's dates and chain up to `anchors`, and refuses an e-CNPJ, another text,
 * a non-company or non-self-issued credential, and a certificate that already co-signed. Returns a new
 * IssuedCredential: the credential gains a `cosignatures` entry (hash, issuer, dates; no CPF), the proof the CMS.
 * Throws KyaError (INVALID_INPUT, CHALLENGE_FAILED, CERTIFICATE_INVALID).
 */
export async function addCosignature(issued: IssuedCredential, cms: string, certChain: (Uint8Array | string)[], opts: { anchors: string[]; now: Date }): Promise<IssuedCredential> {
  if (!issued?.credential || !issued.proof || typeof issued.proof.text !== "string") throw bad("issued: { credential, proof } from assembleCredential is required");
  const c = issued.credential;
  if (c.issuer !== SELF_ISSUER) throw bad(`only a self-issued credential (${SELF_ISSUER}) takes co-signatures`);
  if (!c.principal || isPersonPrincipal(c.principal)) throw bad("only a company credential takes co-signatures of its legal representatives");
  if (!validDate(opts?.now)) throw bad("opts.now must be a valid Date (the clock is the caller's)");
  if (!Array.isArray(opts.anchors) || !opts.anchors.length) throw bad("opts.anchors: the ICP-Brasil trust anchors are required");
  if (typeof cms !== "string" || !cms.trim()) throw bad("cms: the co-signature (base64 DER) is required");
  if (!Array.isArray(certChain)) throw bad("certChain must be an array; [] when the CMS already carries it");
  const full = withCertificates(cms, certChain);
  const icp = await verifyIcpPersonSignature({ cmsBase64: full, challenge: issued.proof.text, anchors: opts.anchors, now: opts.now });
  const existing = c.cosignatures ?? [];
  if (existing.some((x) => x.certificate_sha256 === icp.certificate_sha256)) throw new KyaError("CONFLICT", "this e-CPF certificate already co-signed the credential");
  const entry: Cosignature = { method: "icp-brasil-e-cpf", certificate_sha256: icp.certificate_sha256, issuer: icp.issuer, signed_at: opts.now.toISOString(), not_after: icp.not_after };
  return {
    credential: { ...c, cosignatures: [...existing, entry] },
    proof: { ...issued.proof, cosignatures: [...(issued.proof.cosignatures ?? []), full] }
  };
}

export type CompanyWillCode =
  | "COMPANY_SIGNATURE_INVALID"
  | "NO_COSIGNATURE"
  | "COSIGNATURE_TEXT_MISMATCH"
  | "COSIGNER_CERTIFICATE_INVALID"
  | "COSIGNATURE_NOT_RECORDED"
  | "COSIGNER_NOT_REPRESENTATIVE"
  | "INSUFFICIENT_COSIGNERS";

export interface CosignerCheck {
  /** Hash of the co-signer's e-CPF certificate (null when the CMS did not verify). Never the CPF. */
  certificate_sha256: string | null;
  ok: boolean;
  representative: boolean;
  /** Why the co-signer counts: in the verifier's list, or the person responsible named in the e-CNPJ. */
  basis?: "representatives" | "ecnpj_responsible";
  code?: CompanyWillCode;
  detail: string;
  /** For the caller's revocation check of the e-CPF certificate (checkRevocation); null when it did not verify. */
  revocation: { serial_number: string; issuer_certificate: string | null; crl_urls: string[] } | null;
}

export interface CompanyWillResult {
  ok: boolean;
  /** Why it was refused; absent when accepted. */
  code?: CompanyWillCode;
  detail: string;
  /** Distinct representatives whose valid co-signature was counted. */
  representatives_counted: number;
  cosigners: CosignerCheck[];
}

/**
 * Whether a self-issued company credential expresses the company's will: the e-CNPJ proof verifies
 * (verifySelfIssuedCredential) AND at least `minCosigners` (default 1) distinct CPFs, read from valid e-CPF
 * co-signatures over the same text, are legal representatives. A CPF counts when it is among
 * `representatives(cnpj)` (the verifier's list, e.g. the QSA) or, with `acceptCertificateResponsible`, when it is
 * the CPF of the person responsible named in the e-CNPJ itself (otherName 2.16.76.1.3.4, checked by the
 * registration authority at issuance): no list is needed then. At least one of the two sources is required. Every
 * co-signature in the proof must be recorded in the credential (by certificate hash) and vice versa. Never throws on
 * a bad credential; the result carries no CPF. Revocation of the e-CPF certificates is the caller's (`revocation`).
 */
export async function verifyCompanyWill(
  issued: IssuedCredential,
  opts: { anchors: string[]; now: Date; representatives?: (cnpj: string) => Promise<string[]> | string[]; acceptCertificateResponsible?: boolean; minCosigners?: number }
): Promise<CompanyWillResult> {
  const refuse = (code: CompanyWillCode, detail: string, cosigners: CosignerCheck[] = [], counted = 0): CompanyWillResult => ({ ok: false, code, detail, representatives_counted: counted, cosigners });
  const min = opts?.minCosigners ?? 1;
  if (!Number.isInteger(min) || min < 1) throw bad("minCosigners must be an integer >= 1");
  const byList = typeof opts?.representatives === "function";
  const byResponsible = opts?.acceptCertificateResponsible === true;
  if (opts?.representatives !== undefined && !byList) throw bad("representatives must be (cnpj) => CPFs of the company's legal representatives");
  if (!byList && !byResponsible) throw bad("a source of legal representatives is required: representatives(cnpj), acceptCertificateResponsible, or both");
  const c = issued?.credential;
  if (!c?.principal || isPersonPrincipal(c.principal)) return refuse("COMPANY_SIGNATURE_INVALID", "not a company credential");
  // D-43: signed by a representative's e-CPF alone. There is no e-CNPJ to name a person responsible, so only the
  // verifier's list counts, and the signer is already the first representative.
  const byRepresentative = c.authorized_by?.method === REPRESENTATIVE_METHOD;
  if (byRepresentative && !byList) return refuse("COMPANY_SIGNATURE_INVALID", "a company credential signed by a legal representative needs representatives(cnpj): there is no e-CNPJ to name a person responsible");
  const base = await verifySelfIssuedCredential({ credential: c, proof: issued.proof, anchors: opts.anchors, now: opts.now, ...(byList ? { representatives: opts.representatives! } : {}) });
  if (!base.ok) return refuse("COMPANY_SIGNATURE_INVALID", base.checks.filter((x) => !x.ok).map((x) => `${x.rule}: ${x.detail}`).join("; "));
  const cmsList = issued.proof.cosignatures ?? [];
  const recorded = c.cosignatures ?? [];
  if (!byRepresentative && !cmsList.length && !recorded.length) return refuse("NO_COSIGNATURE", "the credential carries no co-signature by a legal representative (e-CPF)");

  const cnpj = normalizeCnpj(c.principal.cnpj);
  const reps = new Set(byList ? (await opts.representatives!(cnpj)).map((x) => String(x).replace(/\D/g, "")) : []);
  const responsible = byResponsible && !byRepresentative ? ecnpjResponsibleCpf(issued.proof.cms) : null;
  const cosigners: CosignerCheck[] = [];
  const counted = new Set<string>();
  if (byRepresentative) {
    // The base check already found the signer in the list; the CPF is read again only to count distinct people.
    const signer = await verifyIcpPersonSignature({ cmsBase64: issued.proof.cms, challenge: issued.proof.text, anchors: opts.anchors, now: opts.now });
    counted.add(signer.cpf);
  }
  const seenCerts = new Set<string>();
  for (const cms of cmsList) {
    try {
      const icp = await verifyIcpPersonSignature({ cmsBase64: cms, challenge: issued.proof.text, anchors: opts.anchors, now: opts.now });
      const revocation = { serial_number: icp.serial_number, issuer_certificate: icp.issuer_certificate, crl_urls: icp.crl_urls };
      seenCerts.add(icp.certificate_sha256);
      if (!recorded.some((r) => r.certificate_sha256 === icp.certificate_sha256)) {
        cosigners.push({ certificate_sha256: icp.certificate_sha256, ok: false, representative: false, code: "COSIGNATURE_NOT_RECORDED", detail: "the credential does not record this co-signer's certificate", revocation });
        continue;
      }
      const basis = reps.has(icp.cpf) ? ("representatives" as const) : responsible !== null && icp.cpf === responsible ? ("ecnpj_responsible" as const) : null;
      const isRep = basis !== null;
      if (isRep) counted.add(icp.cpf);
      const detail = basis === "representatives" ? "valid co-signature by a legal representative" : basis === "ecnpj_responsible" ? "valid co-signature by the person responsible named in the e-CNPJ" : `the co-signer is not a legal representative of CNPJ ${cnpj}`;
      cosigners.push({ certificate_sha256: icp.certificate_sha256, ok: isRep, representative: isRep, ...(basis ? { basis } : { code: "COSIGNER_NOT_REPRESENTATIVE" as const }), detail, revocation });
    } catch (e) {
      const k = e instanceof KyaError ? e.code : "CHALLENGE_FAILED";
      const code: CompanyWillCode = k === "CERTIFICATE_INVALID" ? "COSIGNER_CERTIFICATE_INVALID" : "COSIGNATURE_TEXT_MISMATCH";
      cosigners.push({ certificate_sha256: null, ok: false, representative: false, code, detail: (e as Error).message, revocation: null });
    }
  }
  for (const r of recorded) {
    if (!seenCerts.has(r.certificate_sha256)) cosigners.push({ certificate_sha256: r.certificate_sha256, ok: false, representative: false, code: "COSIGNATURE_NOT_RECORDED", detail: "the credential records a co-signature the proof does not carry (or it did not verify)", revocation: null });
  }
  // A tampered or unmatched record is a refusal on its own: nothing about the cosignatures may be inconsistent.
  const broken = cosigners.find((x) => x.code && x.code !== "COSIGNER_NOT_REPRESENTATIVE");
  if (broken) return refuse(broken.code!, broken.detail, cosigners, counted.size);
  if (counted.size >= min) return { ok: true, detail: byRepresentative ? `${counted.size} legal representative(s) signed` : `${counted.size} legal representative(s) co-signed`, representatives_counted: counted.size, cosigners };
  if (counted.size === 0) return refuse("COSIGNER_NOT_REPRESENTATIVE", `no co-signer is a legal representative of CNPJ ${cnpj}`, cosigners, 0);
  return refuse("INSUFFICIENT_COSIGNERS", `${counted.size} of ${min} required legal representatives co-signed`, cosigners, counted.size);
}
