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
export function cnpjFromCertificate(cert: X509Certificate): string | null {
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
    if (!/2\.16\.76\.1\.3\.3$/.test(oidStr)) continue;
    const explicit = inner[1] as asn1js.Constructed | undefined;
    const valueBlock = explicit?.valueBlock?.value?.[0] as asn1js.OctetString | asn1js.PrintableString | undefined;
    if (!valueBlock) continue;
    const raw = "valueBlock" in valueBlock && "valueHexView" in valueBlock.valueBlock ? new TextDecoder().decode(valueBlock.valueBlock.valueHexView) : String((valueBlock as { valueBlock: { value: string } }).valueBlock.value);
    const digits = raw.replace(/\D/g, "");
    if (digits.length === 14) return digits;
  }
  return null;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", bytes.slice().buffer as ArrayBuffer));
}

/**
 * Verifies a CMS SignedData (base64 DER) over `challenge` and returns the proof. Throws KyaError
 * CERTIFICATE_INVALID / CHALLENGE_FAILED / CNPJ_MISMATCH. `anchors` are PEM or DER (base64) roots.
 */
export async function verifyIcpSignature(p: { cmsBase64: string; challenge: string; expectedCnpj: string; anchors: string[]; now?: Date; requireChain?: boolean }): Promise<IcpProof> {
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
  // `data` says: it MUST carry exactly the challenge, or any document the company ever signed would pass.
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
  if (!ok) throw new KyaError("CHALLENGE_FAILED", "e-CNPJ signature does not match the challenge");

  // The signer: match SignerInfo's issuerAndSerialNumber against the carried certificates.
  const si = signed.signerInfos[0]!;
  const sid = si.sid as pkijs.IssuerAndSerialNumber;
  const signerCert = certs.find((c) => c.serialNumber.isEqual(sid.serialNumber) && c.issuer.isEqual(sid.issuer)) ?? certs[0]!;
  const der = signerCert.toSchema().toBER(false);
  const x = new X509Certificate(der);
  if (x.notBefore > now || x.notAfter < now) throw new KyaError("CERTIFICATE_INVALID", `certificate valid from ${x.notBefore.toISOString()} to ${x.notAfter.toISOString()}`);

  const cnpj = cnpjFromCertificate(x);
  if (!cnpj) throw new KyaError("CERTIFICATE_INVALID", "certificate has no ICP-Brasil CNPJ (not an e-CNPJ)");
  if (cnpj !== normalizeCnpj(p.expectedCnpj)) throw new KyaError("CNPJ_MISMATCH", `certificate belongs to CNPJ ${cnpj}, not ${normalizeCnpj(p.expectedCnpj)}`);

  if (p.requireChain !== false) {
    if (!trusted.length) throw new KyaError("CERTIFICATE_INVALID", "no ICP-Brasil trust anchors configured");
    const engine = new pkijs.CertificateChainValidationEngine({ certs: certs, trustedCerts: trusted, checkDate: now });
    const chain = await engine.verify();
    if (!chain.result) throw new KyaError("CERTIFICATE_INVALID", `certificate chain not trusted: ${chain.resultMessage}`);
  }

  // The issuing AC: carried in the CMS or among the anchors (the bundle includes the intermediate ACs).
  const issuerCert = [...certs, ...trusted].map((c) => new X509Certificate(c.toSchema().toBER(false))).find((c) => c.subject === x.issuer) ?? null;

  return {
    cnpj,
    certificate_sha256: await sha256Hex(new Uint8Array(der)),
    certificate_subject: x.subject,
    issuer: x.issuer,
    not_before: x.notBefore.toISOString(),
    not_after: x.notAfter.toISOString(),
    signed_at: now.toISOString(),
    serial_number: normalizeSerial(x.serialNumber),
    crl_urls: crlUrlsOf(x),
    issuer_certificate: issuerCert ? b64(issuerCert.rawData) : null
  };
}
