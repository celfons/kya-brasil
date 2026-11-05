/**
 * Revocation of the e-CNPJ certificate (LCR, the ICP-Brasil CRL). Every ICP-Brasil certificate names
 * its CRL distribution points; the AC that issued it signs the CRL. We verify that signature with the
 * issuing AC's certificate, refuse a CRL past its nextUpdate (stale), and look the serial number up.
 * OCSP is not used: ICP-Brasil requires a CRL from every AC (DOC-ICP-04), OCSP is optional.
 * Pure functions: fetching and caching the CRL is the caller's job.
 */
import "reflect-metadata"; // @peculiar/x509 (tsyringe) needs it before import
import { CRLDistributionPointsExtension, Name, X509Certificate, X509CrlReason } from "@peculiar/x509";
import { type ParsedCrl, ecdsaDerToRaw, parseCrlDer } from "./crl-der.js";
export { MAX_CRL_BYTES, MAX_CRL_ENTRIES } from "./crl-der.js";
import { KyaError } from "./types.js";

/** Serial numbers compared as lowercase hex without leading zeros. */
export const normalizeSerial = (hex: string) => hex.toLowerCase().replace(/^0+(?=.)/, "");

/** HTTP(S) URLs of the certificate's CRL distribution points, in the order the AC lists them. */
export function crlUrlsOf(cert: X509Certificate): string[] {
  const ext = cert.getExtension(CRLDistributionPointsExtension);
  if (!ext) return [];
  const urls: string[] = [];
  for (const dp of ext.distributionPoints) {
    for (const name of dp.distributionPoint?.fullName ?? []) {
      const u = name.uniformResourceIdentifier;
      if (u && /^https?:\/\//i.test(u) && !urls.includes(u)) urls.push(u);
    }
  }
  return urls;
}

export interface RevocationStatus {
  revoked: boolean;
  revoked_at: string | null;
  reason: string | null;
  /** RFC 5280 invalidityDate: when the key is known or suspected to have been compromised, if the AC says so. */
  invalidity_date?: string | null;
  crl_this_update: string;
  crl_next_update: string | null;
}

/** A CRL whose signature, issuer and freshness were checked: look serials up without re-parsing. */
export interface VerifiedCrl {
  this_update: string;
  next_update: string | null;
  lookup(serial: string): RevocationStatus;
}

/**
 * Parses and verifies a DER CRL against `issuerCertificate` (base64 DER). Throws REVOCATION_UNAVAILABLE
 * when the CRL cannot be trusted (bad encoding, other issuer, bad signature).
 *
 * `pastNextUpdate` is the caller's choice for a CRL whose nextUpdate has passed: "refuse" throws (the usual
 * reading of RFC 5280); "accept" returns it, still reporting next_update, for callers that bound the risk by
 * the CRL's age instead (Li and Feigenbaum, FC 2001; SPEC section 18).
 */
export async function verifyCrl(p: { crlDer: ArrayBuffer | Uint8Array; issuerCertificate: string; pastNextUpdate: "refuse" | "accept"; now?: Date }): Promise<VerifiedCrl> {
  if (p.pastNextUpdate !== "refuse" && p.pastNextUpdate !== "accept") throw new KyaError("INVALID_INPUT", 'pastNextUpdate is required: "refuse" or "accept"');
  const now = p.now ?? new Date();
  let crl: ParsedCrl;
  let issuer: X509Certificate;
  try {
    crl = parseCrlDer(new Uint8Array(p.crlDer));
    issuer = new X509Certificate(p.issuerCertificate.replace(/-----[^-]+-----|\s+/g, ""));
  } catch (e) {
    throw new KyaError("REVOCATION_UNAVAILABLE", `CRL or issuer certificate is not valid DER: ${(e as Error).message}`);
  }
  const crlIssuer = new Name(ab(crl.issuerDer)).toString();
  if (crlIssuer !== issuer.subject) throw new KyaError("REVOCATION_UNAVAILABLE", `CRL issued by "${crlIssuer}", not by the certificate's AC "${issuer.subject}"`);
  if (!(await verifyCrlSignature(crl, issuer))) throw new KyaError("REVOCATION_UNAVAILABLE", "CRL signature does not match the AC certificate");
  if (p.pastNextUpdate === "refuse" && crl.nextUpdate && crl.nextUpdate < now) throw new KyaError("REVOCATION_UNAVAILABLE", `CRL is stale (nextUpdate ${crl.nextUpdate.toISOString()})`);
  const this_update = crl.thisUpdate.toISOString();
  const next_update = crl.nextUpdate ? crl.nextUpdate.toISOString() : null;
  return {
    this_update,
    next_update,
    lookup(serial: string): RevocationStatus {
      const entry = crl.entry(normalizeSerial(serial));
      return {
        revoked: entry !== null,
        revoked_at: entry ? entry.revocationDate.toISOString() : null,
        reason: entry && entry.reason !== undefined ? (X509CrlReason[entry.reason] ?? String(entry.reason)) : null,
        invalidity_date: entry?.invalidity ? entry.invalidity.toISOString() : null,
        crl_this_update: this_update,
        crl_next_update: next_update
      };
    }
  };
}

// CRL signature algorithms (RFC 4055 / RFC 5758). ICP-Brasil ACs sign with RSA PKCS#1 v1.5 (SHA-256 / SHA-512).
const RSA_PKCS1: Record<string, string> = { "1.2.840.113549.1.1.5": "SHA-1", "1.2.840.113549.1.1.11": "SHA-256", "1.2.840.113549.1.1.12": "SHA-384", "1.2.840.113549.1.1.13": "SHA-512" };
const ECDSA: Record<string, string> = { "1.2.840.10045.4.3.2": "SHA-256", "1.2.840.10045.4.3.3": "SHA-384", "1.2.840.10045.4.3.4": "SHA-512" };
const CURVE_BYTES: Record<string, number> = { "P-256": 32, "P-384": 48, "P-521": 66 };
const ab = (u: Uint8Array) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

/** Verifies the CRL's signature over TBSCertList with the AC's public key (Web Crypto). Unknown algorithms fail. */
async function verifyCrlSignature(crl: ParsedCrl, issuer: X509Certificate): Promise<boolean> {
  const spki = ab(new Uint8Array(issuer.publicKey.rawData));
  try {
    const rsaHash = RSA_PKCS1[crl.signatureAlgorithm];
    if (rsaHash) {
      const key = await crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: rsaHash }, false, ["verify"]);
      return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, ab(crl.signature), ab(crl.tbs));
    }
    const ecHash = ECDSA[crl.signatureAlgorithm];
    if (ecHash) {
      const namedCurve = (issuer.publicKey.algorithm as EcKeyAlgorithm).namedCurve;
      const size = CURVE_BYTES[namedCurve];
      if (!size) return false;
      const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve }, false, ["verify"]);
      return await crypto.subtle.verify({ name: "ECDSA", hash: ecHash }, key, ab(ecdsaDerToRaw(crl.signature, size)), ab(crl.tbs));
    }
  } catch {
    return false;
  }
  throw new KyaError("REVOCATION_UNAVAILABLE", `CRL signature algorithm ${crl.signatureAlgorithm} is not supported`);
}

/** One-shot check of `serial` against a DER CRL signed by `issuerCertificate`; see verifyCrl. */
export async function checkRevocation(p: { crlDer: ArrayBuffer | Uint8Array; serial: string; issuerCertificate: string; pastNextUpdate: "refuse" | "accept"; now?: Date }): Promise<RevocationStatus> {
  return (await verifyCrl(p)).lookup(p.serial);
}

/** RFC 5280 CRL reason codes (section 5.3.1), by name. */
export const CRL_REASONS = ["unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL", "privilegeWithdrawn", "aACompromise"] as const;
export type CrlReason = (typeof CRL_REASONS)[number];

/**
 * D-36: what a revoked certificate does to what it already authorized, decided by whoever relies on it.
 *   - `by_reason`: the effect of each CRL reason the caller has an opinion on: "revoke" (the authorization ends),
 *     "suspend" (it stops while the entry stays, e.g. certificateHold) or "keep" (it stands: the certificate was
 *     replaced or retired without compromise);
 *   - `other`: the effect of any reason not listed, including an entry without a reason. Never "keep": an
 *     unexplained revocation is not ignored.
 * No default: which reasons end a mandate is a legal and risk decision (Código Civil art. 682; SPEC section 11).
 */
export interface CertificateRevocationPolicy {
  by_reason: Partial<Record<CrlReason, "revoke" | "suspend" | "keep">>;
  other: "revoke" | "suspend";
}

/** Throws INVALID_INPUT unless `p` is a complete CertificateRevocationPolicy. */
export function certificateRevocationPolicy(p: CertificateRevocationPolicy): CertificateRevocationPolicy {
  if (!p || typeof p !== "object") throw new KyaError("INVALID_INPUT", "a certificate revocation policy is required: { by_reason, other }");
  if (p.other !== "revoke" && p.other !== "suspend") throw new KyaError("INVALID_INPUT", 'policy.other is required: "revoke" or "suspend" (an unexplained revocation is never ignored)');
  if (!p.by_reason || typeof p.by_reason !== "object") throw new KyaError("INVALID_INPUT", "policy.by_reason is required (it may be empty)");
  for (const [k, v] of Object.entries(p.by_reason)) {
    if (!(CRL_REASONS as readonly string[]).includes(k)) throw new KyaError("INVALID_INPUT", `policy.by_reason.${k} is not an RFC 5280 reason`);
    if (v !== "revoke" && v !== "suspend" && v !== "keep") throw new KyaError("INVALID_INPUT", `policy.by_reason.${k} must be "revoke", "suspend" or "keep"`);
  }
  return { by_reason: { ...p.by_reason }, other: p.other };
}

const isAfter = (a: string | null, b: string) => a !== null && Date.parse(a) > Date.parse(b);

/**
 * What a CRL entry does to an authorization the certificate already signed (D-16, D-36), under the caller's policy.
 * Two rules hold whatever the policy says, because they are about the signature, not about the mandate:
 *   - "keep" applies only when the revocation, and the suspected compromise (invalidityDate) when the AC gives
 *     one, come after the authorization; otherwise the authorization was signed with a certificate already
 *     revoked or already compromised, and it is revoked (MP 2.200-2 art. 10 presumes only a valid certificate);
 *   - without the authorization's date there is nothing to compare: "keep" becomes "revoke".
 * At issuance any entry refuses: a new authorization must be signed with a certificate in force.
 */
export function revocationEffect(r: Pick<RevocationStatus, "revoked" | "revoked_at" | "reason"> & { invalidity_date?: string | null }, authorizedAt: string | null, policy: CertificateRevocationPolicy): "none" | "suspend" | "revoke" {
  const pol = certificateRevocationPolicy(policy);
  if (!r.revoked) return "none";
  const reason = r.reason && (CRL_REASONS as readonly string[]).includes(r.reason) ? (r.reason as CrlReason) : null;
  const effect = (reason && pol.by_reason[reason]) ?? pol.other;
  if (effect !== "keep") return effect;
  if (!authorizedAt || Number.isNaN(Date.parse(authorizedAt))) return "revoke";
  const revokedAfter = isAfter(r.revoked_at, authorizedAt);
  const compromiseAfter = r.invalidity_date ? isAfter(r.invalidity_date, authorizedAt) : true;
  return revokedAfter && compromiseAfter ? "none" : "revoke";
}
