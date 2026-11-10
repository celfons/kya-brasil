/**
 * Time-stamp on the principal's signature (SPEC section 23, D-45).
 *
 * The time a credential records for the authorization (`authorized_by.signed_at`) is the clock of whoever
 * assembled it. In a self-issued credential that is the signer: whoever holds a stolen key can sign after the
 * certificate was revoked and say it signed before. A time-stamp token (RFC 3161) by a time-stamping authority
 * says that this signature already existed at a given time, and the signer cannot choose that time.
 *
 * What is stamped is the signature value of the mandate's CMS (the SignerInfo `signature` octets), as in the
 * CAdES signature-time-stamp attribute (id-aa-signatureTimeStampToken) that ICP-Brasil's AD-RT policies use. The
 * token travels beside the CMS (`proof.timestamp`) or inside it, as that unsigned attribute.
 *
 * Pure: the library builds the request and verifies the token; asking an authority for the token is the
 * caller's. No default: which authorities to trust, and whether a token is required, are the verifier's.
 */
import "reflect-metadata"; // @peculiar/x509 (tsyringe) needs it before import
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { ExtendedKeyUsageExtension, X509Certificate } from "@peculiar/x509";
import { crlUrlsOf, normalizeSerial } from "./revocation.js";
import { KyaError } from "./types.js";

/** id-ct-TSTInfo: the content of a time-stamp token (RFC 3161). */
export const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
/** id-aa-signatureTimeStampToken: the unsigned attribute that carries the token inside the stamped CMS. */
export const OID_SIGNATURE_TIMESTAMP = "1.2.840.113549.1.9.16.2.14";
/** id-kp-timeStamping: the only purpose a time-stamping authority's certificate may have (RFC 3161, 2.3). */
export const OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
const OID_EKU = "2.5.29.37";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
/** Hash algorithms accepted in a token's message imprint. */
const IMPRINT_HASHES: Record<string, string> = { [OID_SHA256]: "SHA-256", "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512" };

let engineReady = false;
function ensureEngine() {
  if (engineReady) return;
  pkijs.setEngine("kya-tsp", new pkijs.CryptoEngine({ name: "kya-tsp", crypto: globalThis.crypto as Crypto }));
  engineReady = true;
}

const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
const b64 = (buf: ArrayBuffer) => {
  let bin = "";
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin);
};
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const refuse = (detail: string) => new KyaError("TIMESTAMP_INVALID", detail);

function signedDataOf(base64: string, what: string): pkijs.SignedData {
  try {
    const ci = pkijs.ContentInfo.fromBER(unb64(base64));
    if (ci.contentType !== OID_SIGNED_DATA) throw new Error("not a SignedData");
    const signed = new pkijs.SignedData({ schema: ci.content });
    if (!signed.signerInfos.length) throw new Error("no signer");
    return signed;
  } catch (e) {
    throw refuse(`${what} is not a CMS SignedData: ${(e as Error).message}`);
  }
}

/** The bytes a signature time-stamp covers: the signature value of the CMS's first signer. */
function signatureValueOf(cmsBase64: string): Uint8Array {
  return new Uint8Array(signedDataOf(cmsBase64, "the stamped signature").signerInfos[0]!.signature.valueBlock.valueHexView);
}

/**
 * The time-stamp request (RFC 3161 TimeStampReq, DER) for a mandate's CMS: SHA-256 of its signature value, with the
 * authority's certificate requested. The caller sends it to the authority it chose (HTTP POST,
 * application/timestamp-query) and gives the token of the answer to addTimestamp.
 */
export async function timestampRequest(cmsBase64: string): Promise<{ der: Uint8Array; imprint_sha256: string }> {
  const digest = await crypto.subtle.digest("SHA-256", signatureValueOf(cmsBase64).slice().buffer as ArrayBuffer);
  const req = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({ hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 }), hashedMessage: new asn1js.OctetString({ valueHex: digest }) }),
    certReq: true
  });
  return { der: new Uint8Array(req.toSchema().toBER(false)), imprint_sha256: hex(digest) };
}

/** The token carried inside the CMS as the signature-time-stamp unsigned attribute (base64 DER), or null. */
export function embeddedTimestamp(cmsBase64: string): string | null {
  let signed: pkijs.SignedData;
  try {
    signed = signedDataOf(cmsBase64, "the signature");
  } catch {
    return null;
  }
  const attr = signed.signerInfos[0]!.unsignedAttrs?.attributes.find((a) => a.type === OID_SIGNATURE_TIMESTAMP);
  const value = attr?.values[0] as asn1js.AsnType | undefined;
  return value ? b64(value.toBER(false)) : null;
}

const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

/**
 * The authority's signature over the token (RFC 5652, 5.4): the signed attributes must carry the digest of the
 * TSTInfo, and the signature is over the DER of those attributes as a SET. A token without signed attributes is
 * refused: RFC 3161 requires them.
 */
async function tokenSignatureVerifies(signed: pkijs.SignedData, signer: pkijs.Certificate, content: Uint8Array): Promise<boolean> {
  const si = signed.signerInfos[0]!;
  const hash = IMPRINT_HASHES[si.digestAlgorithm.algorithmId];
  const digestAttr = si.signedAttrs?.attributes.find((a) => a.type === OID_MESSAGE_DIGEST)?.values[0];
  if (!hash || !si.signedAttrs || !(digestAttr instanceof asn1js.OctetString)) return false;
  const digest = new Uint8Array(await crypto.subtle.digest(hash, content.slice().buffer as ArrayBuffer));
  if (!sameBytes(digest, new Uint8Array(digestAttr.valueBlock.valueHexView))) return false;
  const tbs = new Uint8Array(si.signedAttrs.toSchema().toBER(false));
  tbs[0] = 0x31;
  try {
    return await pkijs.getCrypto(true).verifyWithPublicKey(tbs.buffer as ArrayBuffer, new asn1js.BitString({ valueHex: si.signature.valueBlock.valueHexView.slice().buffer as ArrayBuffer }), signer.subjectPublicKeyInfo, si.signatureAlgorithm, hash);
  } catch {
    return false;
  }
}

/** What a verified token says. Nothing personal: an authority is a service, not a person. */
export interface TimestampProof {
  /** The time the authority attests the signature already existed (TSTInfo genTime), ISO 8601. */
  attested_at: string;
  authority_subject: string;
  authority_certificate_sha256: string;
  /** The authority's policy OID under which the token was issued. */
  policy: string;
  /** For the caller's revocation check of the authority's certificate. */
  revocation: { serial_number: string; issuer_certificate: string | null; crl_urls: string[] };
}

/**
 * Verifies a time-stamp token (base64 DER of the RFC 3161 TimeStampToken) over the signature of `cms`. Refuses, with
 * TIMESTAMP_INVALID, a token that is not one, that stamps other bytes, whose signature does not verify, whose
 * signer is not a time-stamping certificate (extended key usage critical and only id-kp-timeStamping), whose chain
 * does not end in one of `anchors` at the attested time, or whose time is after `now`.
 */
export async function verifyTimestamp(p: { token: string; cms: string; anchors: string[]; now: Date }): Promise<TimestampProof> {
  ensureEngine();
  if (!p.anchors.length) throw refuse("no time-stamping trust anchors configured");
  const signed = signedDataOf(p.token, "the time-stamp token");
  const content = signed.encapContentInfo.eContent;
  if (signed.encapContentInfo.eContentType !== OID_TST_INFO || !content) throw refuse("the token carries no TSTInfo (not an RFC 3161 time-stamp)");
  let tst: pkijs.TSTInfo;
  try {
    tst = pkijs.TSTInfo.fromBER(content.getValue());
  } catch (e) {
    throw refuse(`the token's TSTInfo does not parse: ${(e as Error).message}`);
  }

  const stamped = signatureValueOf(p.cms);
  const hash = IMPRINT_HASHES[tst.messageImprint.hashAlgorithm.algorithmId];
  if (!hash) throw refuse(`message imprint hash ${tst.messageImprint.hashAlgorithm.algorithmId} is not accepted`);
  const digest = new Uint8Array(await crypto.subtle.digest(hash, stamped.slice().buffer as ArrayBuffer));
  if (!sameBytes(digest, new Uint8Array(tst.messageImprint.hashedMessage.valueBlock.valueHexView))) throw refuse("the token stamps another signature than this one");

  const attested = tst.genTime;
  if (Number.isNaN(attested.getTime())) throw refuse("the token has no time");
  if (attested.getTime() > p.now.getTime()) throw refuse(`the token's time ${attested.toISOString()} is after now`);

  const trusted = p.anchors.map((a) => pkijs.Certificate.fromBER(unb64(a.replace(/-----[^-]+-----/g, ""))));
  const certs = (signed.certificates ?? []).filter((c): c is pkijs.Certificate => c instanceof pkijs.Certificate);
  const sid = signed.signerInfos[0]!.sid;
  const signer = sid instanceof pkijs.IssuerAndSerialNumber ? certs.find((c) => c.serialNumber.isEqual(sid.serialNumber) && c.issuer.isEqual(sid.issuer)) : undefined;
  if (!signer) throw refuse("the token does not carry its authority's certificate");
  if (!(await tokenSignatureVerifies(signed, signer, new Uint8Array(content.getValue())))) throw refuse("the token's signature does not verify");

  const der = signer.toSchema().toBER(false);
  const x = new X509Certificate(der);
  const eku = x.getExtension(OID_EKU);
  const usages = eku instanceof ExtendedKeyUsageExtension ? eku.usages : [];
  if (!eku?.critical || usages.length !== 1 || usages[0] !== OID_KP_TIMESTAMPING) throw refuse("the token's signer is not a time-stamping certificate (extended key usage must be critical and only id-kp-timeStamping)");
  if (x.notBefore > attested || x.notAfter < attested) throw refuse("the authority's certificate was not valid at the token's time");
  const chain = await new pkijs.CertificateChainValidationEngine({ certs, trustedCerts: trusted, checkDate: attested }).verify();
  if (!chain.result) throw refuse(`the authority's certificate chain is not trusted: ${chain.resultMessage}`);

  const issuer = [...certs, ...trusted].map((k) => new X509Certificate(k.toSchema().toBER(false))).find((k) => k.subject === x.issuer) ?? null;
  return {
    attested_at: attested.toISOString(),
    authority_subject: x.subject,
    authority_certificate_sha256: hex(await crypto.subtle.digest("SHA-256", der)),
    policy: tst.policy,
    revocation: { serial_number: normalizeSerial(x.serialNumber), issuer_certificate: issuer ? b64(issuer.rawData) : null, crl_urls: crlUrlsOf(x) }
  };
}

/** The verifier's choice about time-stamps. Both members are required: there is no default. */
export interface TimestampPolicy {
  /** Roots of the time-stamping authorities the verifier trusts, PEM or DER (base64). */
  anchors: string[];
  /** true: a credential without a valid token is refused. false: a token is checked when presented. */
  required: boolean;
}

/** Validates the shape of a TimestampPolicy; throws INVALID_INPUT. */
export function timestampPolicy(policy: TimestampPolicy): TimestampPolicy {
  const o = policy as Partial<TimestampPolicy> | null;
  if (!o || !Array.isArray(o.anchors) || !o.anchors.length || !o.anchors.every((a) => typeof a === "string") || typeof o.required !== "boolean") {
    throw new KyaError("INVALID_INPUT", "a timestamp policy needs anchors (at least one) and required (true or false): there is no default");
  }
  return { anchors: o.anchors, required: o.required };
}

/**
 * The rule the proof checks: the token beside the CMS, or the one inside it, verified under the policy. `ok` is
 * false for an invalid token, whatever `required` says, and for a missing one when it is required.
 */
export async function checkTimestamp(p: { cms: string; token?: string | null; policy: TimestampPolicy; now: Date }): Promise<{ ok: boolean; detail: string; proof: TimestampProof | null }> {
  const policy = timestampPolicy(p.policy);
  const token = p.token ?? embeddedTimestamp(p.cms);
  if (!token) return { ok: !policy.required, detail: policy.required ? "no time-stamp presented, and the verifier requires one" : "no time-stamp presented", proof: null };
  try {
    const proof = await verifyTimestamp({ token, cms: p.cms, anchors: policy.anchors, now: p.now });
    return { ok: true, detail: `signature existed at ${proof.attested_at}, attested by ${proof.authority_subject}`, proof };
  } catch (e) {
    return { ok: false, detail: e instanceof KyaError ? e.message : `time-stamp check failed: ${(e as Error).message}`, proof: null };
  }
}
