/**
 * "Sign in with KYA" without the issuer (opt-in): the agent presents its credential and the principal's proof with
 * the request, and the verifier checks them against ICP-Brasil alone (SPEC sections 14, 18, 19 and 20).
 *
 *   KYA-Credential-Document   base64url (no padding) of the credential's JSON
 *   KYA-Principal-Proof       base64url of { text, cms } (section 19, encodePrincipalProofHeader)
 *
 * A credential with `issuer: "urn:kya-brasil:self"` (issued by the principal, section 20) is checked with
 * verifySelfIssuedCredential; any other with verifyPrincipalProof plus the issuer's attestation, verified with a
 * public key the caller lists (`issuerKeys`), so the credential's own fields (id, expiry, status) are not the
 * agent's word. Nothing here fetches: trust anchors, clock and certificate status are the caller's.
 */
import { type Credential as CoreCredential, verifyCompanyWill, isPersonPrincipal, type FreshnessPolicy, type FreshnessPolicyInput, type PrincipalProof, type StatusEvidence, SELF_ISSUER, effectiveStatus, freshnessPolicy, verifyCredentialSignature, verifyPrincipalProof, verifySelfIssuedCredential } from "@kya-brasil/core";
import type { Credential } from "./index.js";
import { fromBase64Url, toBase64Url } from "./base64url.js";

/** What the caller's status callback receives: the credential and where to check its certificate (CRL). */
export interface CertificateStatusQuery {
  credential: Credential;
  /** Serial number, issuing AC certificate (base64 DER, null when the CMS does not carry it) and CRL URLs of the signing certificate. */
  revocation: { serial_number: string; issuer_certificate: string | null; crl_urls: string[] };
}

export interface KyaOfflineOptions {
  /** ICP-Brasil trust anchors (base64 DER or PEM) the principal's certificate must chain to. Required, non-empty. */
  anchors: string[];
  /** The verifier's clock. Required: it decides validity of the certificate, credential, delegation and request window. */
  now: () => Date;
  /**
   * Status of the principal's certificate, for every offline request. Required. Fetch and cache the CRL here (the
   * middleware never does), e.g. `evidenceFromRevocation(await checkRevocation({ crlDer, serial, issuerCertificate,
   * pastNextUpdate, now }))`. May also return `credential` evidence (evidenceFromSignedStatus) for the freshness
   * policy. Throwing answers 502 KYA_CERTIFICATE_STATUS_UNAVAILABLE.
   */
  certificateStatus: (q: CertificateStatusQuery) => StatusEvidence | StatusEvidence[] | Promise<StatusEvidence | StatusEvidence[]>;
  /**
   * Optional status freshness proportional to the amount (section 18): validated with freshnessPolicy at
   * construction; check() then also runs checkFreshAction with the evidence above and the clock. Without it the
   * freshest certificate evidence only has to be in force and not past its valid_until.
   */
  freshness?: FreshnessPolicyInput;
  /**
   * Issuers whose credentials are accepted offline, by `issuer` value, with the Ed25519 public key that signed the
   * credential (published at <issuer>/.well-known/kya.json). A credential from an issuer not listed here is refused;
   * self-issued credentials need no entry.
   */
  issuerKeys?: Record<string, JsonWebKey>;
  /** A request without KYA-Credential-Document goes to the issuer as before when true; refused when false or absent. */
  issuerFallback?: boolean;
  /**
   * Optional (SPEC section 21): a self-issued COMPANY credential is accepted only if it carries the co-signature of
   * a legal representative (e-CPF over the same text the e-CNPJ signed), checked by the core's verifyCompanyWill.
   * Give `representatives(cnpj)` (the verifier's own list, e.g. the QSA), `acceptCertificateResponsible` (the CPF
   * the e-CNPJ names as responsible counts), or both; `minCosigners` defaults to 1. Absent, the e-CNPJ alone is
   * enough, as before. A refusal answers 403 KYA_COMPANY_WILL_REQUIRED with the core's code and detail.
   */
  companyWill?: { representatives?: (cnpj: string) => Promise<string[]> | string[]; acceptCertificateResponsible?: boolean; minCosigners?: number };
}

export interface ResolvedOffline {
  anchors: string[];
  now: () => Date;
  certificateStatus: KyaOfflineOptions["certificateStatus"];
  policy: FreshnessPolicy | null;
  issuerKeys: Record<string, JsonWebKey>;
  issuerFallback: boolean;
  companyWill: KyaOfflineOptions["companyWill"] | null;
}

/** Validates the offline options; throws on anything missing (no defaults for risk parameters). */
export function resolveOffline(o: KyaOfflineOptions): ResolvedOffline {
  const no = (why: string): never => {
    throw new Error(`createKyaAuth offline: ${why}`);
  };
  if (!o || typeof o !== "object") no("expected an object");
  if (!Array.isArray(o.anchors) || !o.anchors.length || o.anchors.some((a) => typeof a !== "string" || !a.trim())) no("anchors (ICP-Brasil trust anchors) are required");
  if (typeof o.now !== "function") no("now (the verifier's clock) is required");
  if (typeof o.certificateStatus !== "function") no("certificateStatus (the certificate's revocation evidence) is required");
  if (o.issuerKeys !== undefined && (!o.issuerKeys || typeof o.issuerKeys !== "object" || Array.isArray(o.issuerKeys))) no("issuerKeys must map issuer -> public JWK");
  if (o.issuerFallback !== undefined && typeof o.issuerFallback !== "boolean") no("issuerFallback must be a boolean");
  if (o.companyWill !== undefined) {
    const cw = o.companyWill;
    if (!cw || typeof cw !== "object") no("companyWill must be an object");
    if (cw.representatives !== undefined && typeof cw.representatives !== "function") no("companyWill.representatives must be (cnpj) => CPFs");
    if (cw.acceptCertificateResponsible !== undefined && typeof cw.acceptCertificateResponsible !== "boolean") no("companyWill.acceptCertificateResponsible must be a boolean");
    if (cw.representatives === undefined && cw.acceptCertificateResponsible !== true) no("companyWill needs representatives(cnpj), acceptCertificateResponsible: true, or both");
    if (cw.minCosigners !== undefined && (!Number.isInteger(cw.minCosigners) || cw.minCosigners < 1)) no("companyWill.minCosigners must be an integer >= 1");
  }
  return { anchors: [...o.anchors], now: o.now, certificateStatus: o.certificateStatus, policy: o.freshness === undefined ? null : freshnessPolicy(o.freshness), issuerKeys: { ...(o.issuerKeys ?? {}) }, issuerFallback: o.issuerFallback ?? false, companyWill: o.companyWill ?? null };
}

/** KYA-Credential-Document value: base64url (no padding) of the credential's JSON. */
export function encodeCredentialHeader(credential: Credential | CoreCredential): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(credential)));
}

/** Parses a KYA-Credential-Document value; throws when it is not base64url JSON of an object. */
export function decodeCredentialHeader(value: string): Credential {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(fromBase64Url(value.trim())));
  } catch {
    throw new Error("KYA-Credential-Document is not base64url JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("KYA-Credential-Document must be a JSON object");
  return parsed as Credential;
}

export type OfflineCredentialResult = { ok: true; revocation: CertificateStatusQuery["revocation"] } | { ok: false; status: 401 | 403; error: string; message: string };

/** Checks the presented credential and proof, without the issuer and without the certificate's status. */
export async function verifyPresentedCredential(o: ResolvedOffline, credential: Credential, proof: PrincipalProof, now: Date): Promise<OfflineCredentialResult> {
  const c = credential as unknown as CoreCredential;
  const failed = (checks: { rule: string; ok: boolean; detail: string }[]) => checks.filter((x) => !x.ok);
  const describe = (checks: { rule: string; ok: boolean; detail: string }[]) => failed(checks).map((x) => `${x.rule}: ${x.detail}`).join("; ");
  if (c.issuer === SELF_ISSUER) {
    const r = await verifySelfIssuedCredential({ credential: c, proof, anchors: o.anchors, now });
    if (r.ok && r.revocation) {
      // Section 21: the company's will, when the verifier requires a representative's co-signature.
      if (o.companyWill && c.principal && !isPersonPrincipal(c.principal)) {
        const will = await verifyCompanyWill({ credential: c, proof }, { anchors: o.anchors, now, ...o.companyWill });
        if (!will.ok) return { ok: false, status: 403, error: "KYA_COMPANY_WILL_REQUIRED", message: `${will.code}: ${will.detail}` };
      }
      return { ok: true, revocation: r.revocation };
    }
    const bad = failed(r.checks);
    // Only the validity window failed: a sound credential that is not (or no longer) in force.
    if (bad.length && bad.every((x) => x.rule === "validity")) return { ok: false, status: 403, error: "KYA_CREDENTIAL_NOT_ACTIVE", message: describe(r.checks) };
    return { ok: false, status: 401, error: "KYA_PRINCIPAL_PROOF_INVALID", message: describe(r.checks) || "proof does not verify" };
  }
  const key = typeof c.issuer === "string" && Object.hasOwn(o.issuerKeys, c.issuer) ? o.issuerKeys[c.issuer] : undefined;
  if (!key) return { ok: false, status: 401, error: "KYA_ISSUER_NOT_TRUSTED", message: `credentials from issuer ${String(c.issuer)} are not accepted offline (list its key in issuerKeys)` };
  const att = await verifyCredentialSignature(c, key);
  if (!att.valid) return { ok: false, status: 401, error: "KYA_CREDENTIAL_SIGNATURE_INVALID", message: `issuer attestation: ${att.reason ?? "does not verify"}` };
  const r = await verifyPrincipalProof({ credential: c, proof, anchors: o.anchors, now });
  if (!r.ok || !r.revocation) return { ok: false, status: 401, error: "KYA_PRINCIPAL_PROOF_INVALID", message: describe(r.checks) || "proof does not verify" };
  const issued = Date.parse(c.issued_at);
  const status = effectiveStatus(c, now);
  if (!Number.isFinite(issued) || issued > now.getTime()) return { ok: false, status: 403, error: "KYA_CREDENTIAL_NOT_ACTIVE", message: `not yet valid (issued ${c.issued_at})` };
  if (status !== "active") return { ok: false, status: 403, error: "KYA_CREDENTIAL_NOT_ACTIVE", message: `credential is ${status}` };
  return { ok: true, revocation: r.revocation };
}

export type CertificateStatusResult = { ok: true; evidence: StatusEvidence[] } | { ok: false; status: 403 | 502; error: string; message: string };

/** Asks the caller for the certificate's status and applies it: the freshest certificate evidence must be in force. */
export async function certificateStatusOf(o: ResolvedOffline, q: CertificateStatusQuery, now: Date): Promise<CertificateStatusResult> {
  let evidence: StatusEvidence[];
  try {
    const r = await o.certificateStatus(q);
    evidence = (Array.isArray(r) ? r : [r]).filter((e): e is StatusEvidence => !!e && typeof e === "object");
  } catch (e) {
    return { ok: false, status: 502, error: "KYA_CERTIFICATE_STATUS_UNAVAILABLE", message: (e as Error)?.message ?? String(e) };
  }
  const nowMs = now.getTime();
  const skewMs = (o.policy?.max_clock_skew_seconds ?? 0) * 1000;
  const certs = evidence.filter((e) => e.kind === "certificate" && Number.isFinite(Date.parse(e.as_of)));
  if (!certs.length) return { ok: false, status: 403, error: "KYA_CERTIFICATE_STATUS_UNKNOWN", message: "no status evidence for the principal's certificate" };
  const freshest = certs.reduce((a, b) => (Date.parse(b.as_of) > Date.parse(a.as_of) ? b : a));
  const from = freshest.source ? ` (${freshest.source})` : "";
  if (Date.parse(freshest.as_of) - nowMs > skewMs) return { ok: false, status: 403, error: "KYA_CERTIFICATE_STATUS_STALE", message: `certificate evidence${from} is dated ${freshest.as_of}, after the verifier's clock` };
  if (!freshest.in_force) return { ok: false, status: 403, error: "KYA_CERTIFICATE_REVOKED", message: `the principal's certificate is not in force${freshest.status ? ` (${freshest.status})` : ""} as of ${freshest.as_of}${from}` };
  const until = freshest.valid_until ? Date.parse(freshest.valid_until) : Number.NaN;
  if (Number.isFinite(until) && until < nowMs && o.policy?.past_valid_until !== "accept") return { ok: false, status: 403, error: "KYA_CERTIFICATE_STATUS_STALE", message: `certificate evidence${from} expired at ${freshest.valid_until}` };
  return { ok: true, evidence };
}
