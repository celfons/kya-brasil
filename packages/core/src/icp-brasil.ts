/**
 * e-CNPJ (ICP-Brasil) proof: the company signs the challenge text with its certificate and sends a
 * CMS/PKCS#7 SignedData (CAdES-BES is a superset; detached or attached). We:
 *   1. parse the CMS, verify the signer's signature over the challenge bytes;
 *   2. check the signer certificate's validity period;
 *   3. extract the CNPJ from the ICP-Brasil otherName extension (OID 2.16.76.1.3.3) and compare;
 *   4. build and verify the chain up to a trusted ICP-Brasil root (anchors supplied by the caller:
 *      the Worker loads the ITI bundle; tests use a throwaway CA).
 * Revocation (LCR) is checked by the caller with ./revocation.ts: the proof carries the serial number,
 * the CRL distribution points and the issuing AC's certificate it needs (all public, no CPF).
 * Only the certificate hash, subject (company) and issuer are kept: never the signer's CPF.
 */
import "reflect-metadata"; // @peculiar/x509 (tsyringe) needs it before import
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { X509Certificate } from "@peculiar/x509";
import { normalizeCnpj } from "./cnpj.js";
import { crlUrlsOf, normalizeSerial } from "./revocation.js";
import { KyaError } from "./types.js";

/** ICP-Brasil otherName: CNPJ of the legal entity (DOC-ICP-04, item 7.1.2). */
export const OID_ICP_CNPJ = "2.16.76.1.3.3";
const OID_SAN = "2.5.29.17";

let engineReady = false;
function ensureEngine() {
  if (engineReady) return;
  pkijs.setEngine("kya", new pkijs.CryptoEngine({ name: "kya", crypto: globalThis.crypto as Crypto }));
  engineReady = true;
}

const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/\s+/g, "")), (c) => c.charCodeAt(0));

/** Content type of a CMS SignedData (RFC 5652, section 5.1). */
export const OID_CMS_SIGNED_DATA = "1.2.840.113549.1.7.2";

/**
 * The SignedData inside a DER or BER ContentInfo. The outer content type must say SignedData: PKI.js decodes the
 * content whatever the type says, so a CMS relabelled as another type would be read as if it were one.
 */
export function signedDataOf(der: Uint8Array): { contentInfo: pkijs.ContentInfo; signed: pkijs.SignedData } {
  const contentInfo = pkijs.ContentInfo.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer);
  if (contentInfo.contentType !== OID_CMS_SIGNED_DATA) throw new Error(`content type ${contentInfo.contentType} is not SignedData`);
  return { contentInfo, signed: new pkijs.SignedData({ schema: contentInfo.content }) };
}
const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

export interface IcpProof {
  cnpj: string;
  certificate_sha256: string;
  certificate_subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  signed_at: string;
  /** Hex serial number of the e-CNPJ certificate, the key of its CRL entry. */
  serial_number: string;
  /** CRL distribution points named by the certificate. */
  crl_urls: string[];
  /** Base64 DER of the AC certificate that issued it (verifies the CRL), or null when not found. */
  issuer_certificate: string | null;
}

/** CNPJ carried by the certificate's ICP-Brasil otherName, or null when it is not a PJ certificate. */
/** Raw value of an ICP-Brasil otherName in the Subject Alternative Name (OID 2.16.76.1.3.<n>), or null. */
function otherNameValue(cert: X509Certificate, oidSuffix: string): string | null {
  const san = cert.extensions.find((e) => e.type === OID_SAN);
  if (!san) return null;
  const parsed = asn1js.fromBER(san.value);
  if (parsed.offset === -1) return null;
  const names = parsed.result as asn1js.Sequence;
  for (const gn of names.valueBlock.value) {
    // otherName is [0] IMPLICIT SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
    const block = gn as asn1js.Constructed;
    if (block.idBlock.tagClass !== 3 || block.idBlock.tagNumber !== 0) continue;
    const inner = block.valueBlock.value;
    const oid = inner[0] as asn1js.ObjectIdentifier | undefined;
    const oidStr = oid?.valueBlock?.toString?.() ?? "";
    if (oidStr !== `2.16.76.1.3.${oidSuffix}`) continue;
    const explicit = inner[1] as asn1js.Constructed | undefined;
    const valueBlock = explicit?.valueBlock?.value?.[0] as asn1js.OctetString | asn1js.PrintableString | undefined;
    if (!valueBlock) continue;
    const raw = "valueBlock" in valueBlock && "valueHexView" in valueBlock.valueBlock ? new TextDecoder().decode(valueBlock.valueBlock.valueHexView) : String((valueBlock as { valueBlock: { value: string } }).valueBlock.value);
    return raw;
  }
  return null;
}

const OID_DN_SERIAL_NUMBER = "2.5.4.5";

/**
 * serialNumber attribute (OID 2.5.4.5) of the subject's Distinguished Name, or null. Resolução CG ICP-Brasil
 * 211/2024, art. 8, puts there the CPF of a natural person's certificate and the CNPJ of an electronic seal; in the
 * seal, the CNPJ otherName becomes optional after 31 Dec 2028 (DOC-ICP-04 v8.3, Anexo I).
 */
function subjectSerialNumber(cert: X509Certificate): string | null {
  const values = cert.subjectName.getField(OID_DN_SERIAL_NUMBER);
  return values.length === 1 ? values[0]! : null;
}

export function cnpjFromCertificate(cert: X509Certificate): string | null {
  // Alphanumeric since 2026 (IN RFB 2.229/2024): letters in the first 12 positions, digits in the 2 check digits.
  const isCnpj = (v: string | null): string | null => {
    const cnpj = v === null ? "" : normalizeCnpj(v);
    return /^[0-9A-Z]{12}\d{2}$/.test(cnpj) ? cnpj : null;
  };
  // The otherName first (every profile before 2029); then the DN serialNumber (the seal, once the otherName is optional).
  return isCnpj(otherNameValue(cert, "3")) ?? isCnpj(subjectSerialNumber(cert));
}

const OID_CERTIFICATE_POLICIES = "2.5.29.32";
const ICP_POLICY_PREFIX = "2.16.76.1.2.";

/**
 * ICP-Brasil certificate types named by the certificate's policy OIDs, 2.16.76.1.2.<type>.<n> (DOC-ICP-04 v8.3,
 * item 1.2): "1" A1, "3" A3, "4" A4, "201" SE-S, "202" SE-H, "401" AE-S, "402" AE-H and so on. Empty when the
 * certificate names no ICP-Brasil policy (a test certificate, or another PKI).
 */
export function icpCertificateTypes(cert: X509Certificate): string[] {
  const ext = cert.extensions.find((e) => e.type === OID_CERTIFICATE_POLICIES);
  if (!ext) return [];
  const parsed = asn1js.fromBER(ext.value);
  if (parsed.offset === -1) return [];
  const types: string[] = [];
  for (const info of (parsed.result as asn1js.Sequence).valueBlock.value) {
    const oid = ((info as asn1js.Sequence).valueBlock?.value?.[0] as asn1js.ObjectIdentifier | undefined)?.valueBlock?.toString?.() ?? "";
    if (oid.startsWith(ICP_POLICY_PREFIX)) types.push(oid.slice(ICP_POLICY_PREFIX.length).split(".")[0]!);
  }
  return types;
}

/** Electronic seal types: SE-S (software) and SE-H (hardware), issued to legal persons only. */
export const ICP_SEAL_TYPES: readonly string[] = ["201", "202"];

/**
 * Is this an electronic seal certificate (SE-S or SE-H)? A seal attests the origin and integrity of a document. It
 * may not sign as the company's will: Resolução CG ICP-Brasil 211/2024, art. 4, and DOC-ICP-04 v8.3, item 1.4.2.2.
 * Its key usage still has digitalSignature, so only the policy OID tells it from a signature certificate.
 */
export function isElectronicSeal(cert: X509Certificate): boolean {
  return icpCertificateTypes(cert).some((t) => ICP_SEAL_TYPES.includes(t));
}

/** OID 2.16.76.1.3.1: data of the e-CPF holder, "ddmmaaaa" birth date followed by the 11-digit CPF (DOC-ICP-04). */
export const OID_ICP_PERSON = "2.16.76.1.3.1";

/**
 * CPF of an e-CPF (natural person) certificate: from the 2.16.76.1.3.1 otherName (positions 9 to 19), or the
 * common name suffix ":<11 digits>" as a fallback. Null for an e-CNPJ or any other certificate.
 */
export function cpfFromCertificate(cert: X509Certificate): string | null {
  if (cnpjFromCertificate(cert)) return null;
  const data = otherNameValue(cert, "1")?.replace(/\D/g, "") ?? null;
  if (data && data.length >= 19) return data.slice(8, 19);
  // Resolução CG ICP-Brasil 211/2024, art. 8: the DN serialNumber of a natural person's certificate holds the CPF.
  const serial = subjectSerialNumber(cert);
  if (serial !== null && /^\d{11}$/.test(serial)) return serial;
  const cn = /CN=([^,]+)/.exec(cert.subject)?.[1] ?? "";
  return /:(\d{11})\s*$/.exec(cn)?.[1] ?? null;
}

/**
 * OID 2.16.76.1.3.4: data of the person responsible for an e-CNPJ before the Receita Federal, "ddmmaaaa" birth date
 * followed by the 11-digit CPF (DOC-ICP-04), the same layout as 2.16.76.1.3.1.
 */
export const OID_ICP_RESPONSIBLE = "2.16.76.1.3.4";

/** CPF of the person responsible named in an e-CNPJ (2.16.76.1.3.4), or null for any other certificate. */
export function responsibleCpfFromCertificate(cert: X509Certificate): string | null {
  if (!cnpjFromCertificate(cert)) return null;
  const data = otherNameValue(cert, "4")?.replace(/\D/g, "") ?? null;
  const cpf = data && data.length >= 19 ? data.slice(8, 19) : null;
  return cpf && /^\d{11}$/.test(cpf) && !/^(\d)\1{10}$/.test(cpf) ? cpf : null;
}

/**
 * CPF of the person responsible named in the e-CNPJ that signed `cmsBase64`, or null. Reads the signer certificate
 * only: call it after the CMS was verified (verifyIcpSignature), never instead. The CPF is for the caller to compare
 * at once and forget: never store or return it.
 */
export function ecnpjResponsibleCpf(cmsBase64: string): string | null {
  try {
    const { signed } = signedDataOf(unb64(cmsBase64));
    const certs = (signed.certificates ?? []).filter((c): c is pkijs.Certificate => c instanceof pkijs.Certificate);
    const sid = signed.signerInfos[0]?.sid as pkijs.IssuerAndSerialNumber | undefined;
    const signer = (sid && certs.find((c) => c.serialNumber.isEqual(sid.serialNumber) && c.issuer.isEqual(sid.issuer))) ?? certs[0];
    return signer ? responsibleCpfFromCertificate(new X509Certificate(signer.toSchema().toBER(false))) : null;
  } catch {
    return null;
  }
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", bytes.slice().buffer as ArrayBuffer));
}

/** What every ICP-Brasil signature check yields before the identity (CNPJ or CPF) is read. */
interface CheckedCms {
  x: X509Certificate;
  der: ArrayBuffer;
  certs: pkijs.Certificate[];
  trusted: pkijs.Certificate[];
  now: Date;
}

/**
 * Shared steps: parse the CMS, require attached content to equal the text, verify the signature, pick the signer
 * certificate, check its dates, run `identify` (which throws for the wrong kind of certificate), then the chain.
 */
async function checkCms(p: { cmsBase64: string; challenge: string; anchors: string[]; now?: Date; requireChain?: boolean }, identify: (x: X509Certificate) => void): Promise<CheckedCms> {
  ensureEngine();
  const now = p.now ?? new Date();
  let signed: pkijs.SignedData;
  try {
    signed = signedDataOf(unb64(p.cmsBase64)).signed;
  } catch (e) {
    throw new KyaError("CHALLENGE_FAILED", `signature is not a CMS SignedData: ${(e as Error).message}`);
  }
  if (!signed.signerInfos.length) throw new KyaError("CHALLENGE_FAILED", "CMS has no signer");
  const certs = (signed.certificates ?? []).filter((c): c is pkijs.Certificate => c instanceof pkijs.Certificate);
  if (!certs.length) throw new KyaError("CERTIFICATE_INVALID", "CMS carries no signer certificate");
  const trusted = p.anchors.map((a) => pkijs.Certificate.fromBER(unb64(a.replace(/-----[^-]+-----/g, ""))));

  const data = new TextEncoder().encode(p.challenge);
  // An attached CMS (the .p7s carries the signed text) is verified over its own content by pkijs, whatever
  // `data` says: it MUST carry exactly the challenge, or any document ever signed would pass.
  const embedded = signed.encapContentInfo.eContent;
  if (embedded) {
    const content = new Uint8Array(embedded.getValue());
    if (content.length !== data.length || !content.every((b, i) => b === data[i])) {
      throw new KyaError("CHALLENGE_FAILED", "the signed content is not the challenge text (sign exactly the challenge, without extra line breaks)");
    }
  }
  let ok = false;
  try {
    ok = await signed.verify({ signer: 0, data: data.buffer as ArrayBuffer, trustedCerts: trusted, checkChain: false, checkDate: now });
  } catch (e) {
    throw new KyaError("CHALLENGE_FAILED", `signature verification failed: ${(e as Error).message}`);
  }
  if (!ok) throw new KyaError("CHALLENGE_FAILED", "the ICP-Brasil signature does not match the challenge");

  // The signer: match SignerInfo's issuerAndSerialNumber against the carried certificates.
  const si = signed.signerInfos[0]!;
  const sid = si.sid as pkijs.IssuerAndSerialNumber;
  const signerCert = certs.find((c) => c.serialNumber.isEqual(sid.serialNumber) && c.issuer.isEqual(sid.issuer)) ?? certs[0]!;
  const der = signerCert.toSchema().toBER(false);
  const x = new X509Certificate(der);
  if (x.notBefore > now || x.notAfter < now) throw new KyaError("CERTIFICATE_INVALID", `certificate valid from ${x.notBefore.toISOString()} to ${x.notAfter.toISOString()}`);

  // A seal is not a signature of will, whoever it names: refused before the identity is even read.
  if (isElectronicSeal(x)) {
    throw new KyaError("CERTIFICATE_INVALID", "this is an electronic seal certificate (SE-S or SE-H): it attests origin and integrity and may not sign as the company's will (Resolução CG ICP-Brasil 211/2024, art. 4; DOC-ICP-04, item 1.4.2.2). Sign with a natural person's certificate");
  }

  identify(x);

  if (p.requireChain !== false) {
    if (!trusted.length) throw new KyaError("CERTIFICATE_INVALID", "no ICP-Brasil trust anchors configured");
    const engine = new pkijs.CertificateChainValidationEngine({ certs: certs, trustedCerts: trusted, checkDate: now });
    const chain = await engine.verify();
    if (!chain.result) throw new KyaError("CERTIFICATE_INVALID", `certificate chain not trusted: ${chain.resultMessage}`);
  }
  return { x, der, certs, trusted, now };
}

/** The issuing AC: carried in the CMS or among the anchors (the bundle includes the intermediate ACs). */
function issuerCertificateOf(c: CheckedCms): string | null {
  const issuerCert = [...c.certs, ...c.trusted].map((k) => new X509Certificate(k.toSchema().toBER(false))).find((k) => k.subject === c.x.issuer) ?? null;
  return issuerCert ? b64(issuerCert.rawData) : null;
}

/**
 * Verifies a CMS SignedData (base64 DER) over `challenge` by an e-CNPJ and returns the proof. Throws KyaError
 * CERTIFICATE_INVALID / CHALLENGE_FAILED / CNPJ_MISMATCH. `anchors` are PEM or DER (base64) roots.
 */
export async function verifyIcpSignature(p: { cmsBase64: string; challenge: string; expectedCnpj: string; anchors: string[]; now?: Date; requireChain?: boolean }): Promise<IcpProof> {
  let cnpj = "";
  const c = await checkCms(p, (x) => {
    const found = cnpjFromCertificate(x);
    if (!found) throw new KyaError("CERTIFICATE_INVALID", cpfFromCertificate(x) ? "this is a natural person's certificate (e-CPF); sign with the company's e-CNPJ" : "certificate has no ICP-Brasil CNPJ (not an e-CNPJ)");
    if (found !== normalizeCnpj(p.expectedCnpj)) throw new KyaError("CNPJ_MISMATCH", `certificate belongs to CNPJ ${found}, not ${normalizeCnpj(p.expectedCnpj)}`);
    cnpj = found;
  });
  return {
    cnpj,
    certificate_sha256: await sha256Hex(new Uint8Array(c.der)),
    certificate_subject: c.x.subject,
    issuer: c.x.issuer,
    not_before: c.x.notBefore.toISOString(),
    not_after: c.x.notAfter.toISOString(),
    signed_at: c.now.toISOString(),
    serial_number: normalizeSerial(c.x.serialNumber),
    crl_urls: crlUrlsOf(c.x),
    issuer_certificate: issuerCertificateOf(c)
  };
}

/** e-CPF proof (D-29). `cpf` is for the caller to key-hash at once and forget: never store or return it. No subject (name). */
export interface IcpPersonProof {
  cpf: string;
  certificate_sha256: string;
  issuer: string;
  not_before: string;
  not_after: string;
  signed_at: string;
  serial_number: string;
  crl_urls: string[];
  issuer_certificate: string | null;
}

/** Verifies a CMS over `challenge` by a natural person's e-CPF (D-29). Refuses an e-CNPJ. */
export async function verifyIcpPersonSignature(p: { cmsBase64: string; challenge: string; anchors: string[]; now?: Date; requireChain?: boolean }): Promise<IcpPersonProof> {
  let cpf = "";
  const c = await checkCms(p, (x) => {
    if (cnpjFromCertificate(x)) throw new KyaError("CERTIFICATE_INVALID", "this is a company certificate (e-CNPJ); a person signs with their e-CPF");
    const found = cpfFromCertificate(x);
    if (!found) throw new KyaError("CERTIFICATE_INVALID", "certificate has no ICP-Brasil CPF (not an e-CPF)");
    cpf = found;
  });
  return {
    cpf,
    certificate_sha256: await sha256Hex(new Uint8Array(c.der)),
    issuer: c.x.issuer,
    not_before: c.x.notBefore.toISOString(),
    not_after: c.x.notAfter.toISOString(),
    signed_at: c.now.toISOString(),
    serial_number: normalizeSerial(c.x.serialNumber),
    crl_urls: crlUrlsOf(c.x),
    issuer_certificate: issuerCertificateOf(c)
  };
}
