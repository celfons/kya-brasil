/**
 * Revocation of the e-CNPJ certificate (LCR, the ICP-Brasil CRL). Every ICP-Brasil certificate names
 * its CRL distribution points; the AC that issued it signs the CRL. We verify that signature with the
 * issuing AC's certificate, refuse a CRL past its nextUpdate (stale), and look the serial number up.
 * OCSP is not used: ICP-Brasil requires a CRL from every AC (DOC-ICP-04), OCSP is optional.
 * Pure functions: fetching and caching the CRL is the caller's job.
 */
import "reflect-metadata"; // @peculiar/x509 (tsyringe) needs it before import
import { CRLDistributionPointsExtension, X509Certificate, X509Crl, X509CrlReason } from "@peculiar/x509";
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
 * when the CRL cannot be trusted (bad encoding, other issuer, bad signature, stale).
 */
export async function verifyCrl(p: { crlDer: ArrayBuffer | Uint8Array; issuerCertificate: string; now?: Date }): Promise<VerifiedCrl> {
  const now = p.now ?? new Date();
  let crl: X509Crl;
  let issuer: X509Certificate;
  try {
    crl = new X509Crl(new Uint8Array(p.crlDer));
    issuer = new X509Certificate(p.issuerCertificate.replace(/-----[^-]+-----|\s+/g, ""));
  } catch (e) {
    throw new KyaError("REVOCATION_UNAVAILABLE", `CRL or issuer certificate is not valid DER: ${(e as Error).message}`);
  }
  if (crl.issuer !== issuer.subject) throw new KyaError("REVOCATION_UNAVAILABLE", `CRL issued by "${crl.issuer}", not by the certificate's AC "${issuer.subject}"`);
  if (!(await crl.verify({ publicKey: issuer }, globalThis.crypto as Crypto))) throw new KyaError("REVOCATION_UNAVAILABLE", "CRL signature does not match the AC certificate");
  if (crl.nextUpdate && crl.nextUpdate < now) throw new KyaError("REVOCATION_UNAVAILABLE", `CRL is stale (nextUpdate ${crl.nextUpdate.toISOString()})`);
  const this_update = crl.thisUpdate.toISOString();
  const next_update = crl.nextUpdate ? crl.nextUpdate.toISOString() : null;
  const entries = new Map(crl.entries.map((e) => [normalizeSerial(e.serialNumber), e] as const));
  return {
    this_update,
    next_update,
    lookup(serial: string): RevocationStatus {
      const entry = entries.get(normalizeSerial(serial)) ?? null;
      return {
        revoked: entry !== null,
        revoked_at: entry ? entry.revocationDate.toISOString() : null,
        reason: entry && entry.reason !== undefined ? (X509CrlReason[entry.reason] ?? String(entry.reason)) : null,
        crl_this_update: this_update,
        crl_next_update: next_update
      };
    }
  };
}

/** One-shot check of `serial` against a DER CRL signed by `issuerCertificate`; see verifyCrl. */
export async function checkRevocation(p: { crlDer: ArrayBuffer | Uint8Array; serial: string; issuerCertificate: string; now?: Date }): Promise<RevocationStatus> {
  return (await verifyCrl(p)).lookup(p.serial);
}

/**
 * What a CRL entry does to a credential the certificate already authorized (D-16):
 *   - certificateHold: suspend (the AC may lift it; the review reinstates when the entry disappears);
 *   - superseded / cessationOfOperation dated after the authorization: nothing, the company replaced or
 *     retired the certificate without compromise and its signature stands (registration is checked apart);
 *   - anything else (unspecified, keyCompromise, privilegeWithdrawn, ...): revoke.
 * At issuance any entry refuses: a new authorization must be signed with a certificate in force.
 */
export function revocationEffect(r: Pick<RevocationStatus, "revoked" | "revoked_at" | "reason">, authorizedAt: string | null): "none" | "suspend" | "revoke" {
  if (!r.revoked) return "none";
  if (r.reason === "certificateHold") return "suspend";
  const benign = r.reason === "superseded" || r.reason === "cessationOfOperation";
  if (benign && authorizedAt && r.revoked_at && Date.parse(r.revoked_at) > Date.parse(authorizedAt)) return "none";
  return "revoke";
}
