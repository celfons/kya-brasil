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
/** Digits of an ICP-Brasil otherName in the Subject Alternative Name (OID 2.16.76.1.3.<n>), or null. */
function otherNameDigits(cert: X509Certificate, oidSuffix: string): string | null {
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
    return raw.replace(/\D/g, "");
  }
  return null;
}

export function cnpjFromCertificate(cert: X509Certificate): string | null {
  const digits = otherNameDigits(cert, "3");
  return digits && digits.length === 14 ? digits : null;
}

/** OID 2.16.76.1.3.1: data of the e-CPF holder, "ddmmaaaa" birth date followed by the 11-digit CPF (DOC-ICP-04). */
export const OID_ICP_PERSON = "2.16.76.1.3.1";

/**
 * CPF of an e-CPF (natural person) certificate: from the 2.16.76.1.3.1 otherName (positions 9 to 19), or the
 * common name suffix ":<11 digits>" as a fallback. Null for an e-CNPJ or any other certificate.
 */
export function cpfFromCertificate(cert: X509Certificate): string | null {
  if (cnpjFromCertificate(cert)) return null;
  const data = otherNameDigits(cert, "1");
  if (data && data.length >= 19) return data.slice(8, 19);
  const cn = /CN=([^,]+)/.exec(cert.subject)?.[1] ?? "";
  return /:(\d{11})\s*$/.exec(cn)?.[1] ?? null;
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
  let cms: pkijs.ContentInfo;
  let signed: pkijs.SignedData;
  try {
    const der = unb64(p.cmsBase64);
    cms = pkijs.ContentInfo.fromBER(der);
    signed = new pkijs.SignedData({ schema: cms.content });
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
