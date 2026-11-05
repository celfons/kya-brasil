/**
 * Issuance by the principal (D-37, docs/SPEC.md section 20): the holder of the e-CNPJ or e-CPF is the issuer.
 * There is no intermediary service: the principal builds the mandate, signs with its ICP-Brasil certificate the
 * exact text this module returns, and assembles the credential and the proof its agent presents. A delegating
 * agent is, in the same way, the issuer of its sub-agent's mandate.
 *
 * Symmetric to verification and built on the same functions, so the two cannot drift apart:
 *   buildMandate          validateMandate (+ every risk field required) and mandateSha256 (canonical JSON, section 7)
 *   mandateSigningInput   challengeText / personChallengeText: the text the certificate signs (D-33)
 *   assembleCredential    verifyIcpSignature / verifyIcpPersonSignature, buildCredential / buildPersonCredential,
 *                         and verifySelfIssuedCredential on the result before it is returned
 *   buildDelegation       prepareDelegation (+ every risk field required); assembleDelegation runs
 *                         verifyDelegationChain before returning the signed link
 *
 * Signature format (what verification accepts): CMS/PKCS#7 SignedData over the UTF-8 bytes of the text, detached
 * or attached (CAdES-BES is a superset), digest SHA-256, RSA PKCS#1 v1.5 (sha256WithRSAEncryption). Any ICP-Brasil
 * signer that produces it fits: an A1 file through openPfx, a token or HSM through buildDetachedCms with a raw-sign
 * callback, a cloud certificate through cloudSigner. This module never touches a token (no PKCS#11, no PIN).
 *
 * Pure: no network, no storage, no clock (`now` is always the caller's) and no default for any risk parameter.
 */
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { canonicalize } from "./attestation.js";
import { challengeText, normalizeAgentKey } from "./challenge.js";
import { isValidCnpj, normalizeCnpj } from "./cnpj.js";
import { buildCredential, buildPersonCredential, effectiveStatus, mandateSha256 } from "./credential.js";
import { type Delegation, type DelegationAnchor, prepareDelegation, verifyDelegationChain } from "./delegation.js";
import { verifyIcpPersonSignature, verifyIcpSignature } from "./icp-brasil.js";
import { validateMandate } from "./mandate.js";
import { personChallengeText } from "./person.js";
import { type PrincipalProof, type PrincipalProofCheck, verifyPrincipalProof } from "./principal-proof.js";
import { type AgentKey, type Credential, type DelegationPolicy, type Mandate, type PaymentInstrument, KyaError, isPersonPrincipal } from "./types.js";

/**
 * The `issuer` of a credential issued by its own principal. It goes in the signed text (`issuer:` line) and in the
 * credential, so a verifier tells at once that no service vouches for the credential's status: only the
 * certificate (signature, chain, CRL) and the credential's own expiry do.
 */
export const SELF_ISSUER = "urn:kya-brasil:self";

/** Fields every issued mandate must state: no default stands in for a risk decision (an empty list is explicit: any). */
export const MANDATE_REQUIRED_FIELDS = ["actions", "max_per_operation", "max_per_day", "currencies", "counterparties", "payment_instruments", "valid_from", "valid_until", "delegation"] as const;

/** A mandate to issue. Every reserved field is required; `delegation: null` says, explicitly, "may not delegate". */
export interface MandateTerms {
  actions: string[];
  max_per_operation: { amount: number; currency: string };
  max_per_day: { amount: number; currency: string };
  currencies: string[];
  /** CNPJs, domains (`*.domain` for subdomains) or wallet addresses; `[]` = any counterparty, stated explicitly. */
  counterparties: string[];
  /** `[]` = any instrument, stated explicitly. */
  payment_instruments: PaymentInstrument[];
  valid_from: string;
  valid_until: string;
  delegation: DelegationPolicy | null;
  /** Extensions are carried in the credential and never evaluated (SPEC section 5). */
  [extension: string]: unknown;
}

export interface MandateInput {
  /** Identifier of the credential, chosen by the principal (a UUID is a good choice). Goes into the signed text. */
  credential_id: string;
  /** The agent's public key: evm address, Ed25519 (web-bot-auth) or ERC-8004 identity. */
  agent: { kind: unknown; id: unknown };
  /** Who answers for the agent. A person gives nothing personal: the e-CPF that signs identifies them. */
  principal: { kind: "company"; cnpj: string } | { kind: "person" };
  mandate: MandateTerms;
  /** Credential lifetime in seconds (D-35). Capped by `valid_until` here and by the certificate's notAfter at assembly. */
  ttl_seconds: number;
  /** The issuance time. */
  now: Date;
}

/** A built mandate: everything the certificate will sign, in canonical form. Do not edit it after building. */
export interface BuiltMandate {
  version: 1;
  credential_id: string;
  issuer: typeof SELF_ISSUER;
  agent: AgentKey;
  principal: { kind: "company"; cnpj: string } | { kind: "person" };
  mandate: Mandate;
  /** SHA-256 of the canonical JSON of `mandate` (mandateSha256): what the signed text commits to. */
  mandate_sha256: string;
  issued_at: string;
  /** Upper bound of the credential's expiry, signed in the text's `expires:` line. */
  expires_at: string;
}

/** What the certificate signs: the text, its exact bytes (UTF-8, no trailing newline) and their SHA-256. */
export interface SigningInput {
  text: string;
  bytes: Uint8Array;
  /** Lowercase hex SHA-256 of `bytes`: the CMS messageDigest attribute, for signers that take a precomputed hash. */
  sha256: string;
}

/** What the agent holds and presents: the credential and the principal's proof (KYA-Principal-Proof). */
export interface IssuedCredential {
  credential: Credential;
  proof: PrincipalProof;
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const bad = (why: string) => new KyaError("INVALID_INPUT", why);
const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

function requireDate(now: unknown, what = "now"): Date {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw bad(`${what} must be a valid Date (the clock is the caller's)`);
  return now;
}

/**
 * Checks that a mandate states every risk field (MANDATE_REQUIRED_FIELDS), validates it with validateMandate (the
 * verifier's own schema) and returns it normalized, with `delegation: null` removed (absent = may not delegate).
 */
export function requireMandateTerms(input: unknown, where = "mandate"): Mandate {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw bad(`${where} must be a JSON object`);
  const terms = input as Record<string, unknown>;
  const missing = MANDATE_REQUIRED_FIELDS.filter((k) => terms[k] === undefined);
  if (missing.length) throw bad(`${where}: missing ${missing.join(", ")} (no default stands in for a risk decision; use [] for "any" and delegation: null for "may not delegate")`);
  if (!Array.isArray(terms.actions) || terms.actions.length === 0) throw bad(`${where}.actions: list at least one action`);
  const { delegation, ...rest } = terms;
  return validateMandate(delegation === null ? rest : { ...rest, delegation });
}

/**
 * Builds the mandate a principal issues to its agent: validated as the verifier validates it, every risk field
 * stated, and bound to the agent, the principal, the credential id and the issuance window. Throws INVALID_INPUT on
 * anything verification would refuse (and on any missing risk field).
 */
export async function buildMandate(input: MandateInput): Promise<BuiltMandate> {
  if (!input || typeof input !== "object") throw bad("input must be an object");
  const now = requireDate(input.now);
  if (typeof input.credential_id !== "string" || !ID.test(input.credential_id)) throw bad("credential_id: 1 to 128 characters, letters, digits and . _ : - (it goes into the signed text)");
  if (!input.agent || typeof input.agent !== "object") throw bad("agent: { kind, id } is required");
  const agent = normalizeAgentKey(input.agent);
  const p = input.principal as { kind?: unknown; cnpj?: unknown } | undefined;
  let principal: BuiltMandate["principal"];
  if (p?.kind === "company") {
    if (typeof p.cnpj !== "string" || !isValidCnpj(p.cnpj)) throw bad("principal.cnpj must be a valid CNPJ");
    principal = { kind: "company", cnpj: normalizeCnpj(p.cnpj) };
  }
  else if (p?.kind === "person") principal = { kind: "person" };
  else throw bad('principal.kind must be "company" (with cnpj) or "person"');
  const mandate = requireMandateTerms(input.mandate);
  const ttl = input.ttl_seconds;
  if (typeof ttl !== "number" || !Number.isFinite(ttl) || ttl <= 0) throw bad("ttl_seconds must be a positive number of seconds (the credential lifetime is the caller's decision)");
  const until = Date.parse(mandate.valid_until!);
  if (until <= now.getTime()) throw bad(`mandate.valid_until: ${mandate.valid_until} is not after now`);
  const expires = Math.min(now.getTime() + ttl * 1000, until);
  return {
    version: 1,
    credential_id: input.credential_id,
    issuer: SELF_ISSUER,
    agent,
    principal,
    mandate,
    mandate_sha256: await mandateSha256(mandate),
    issued_at: now.toISOString(),
    expires_at: new Date(expires).toISOString()
  };
}

/** Re-checks a built mandate (it may have travelled between building and signing). */
async function checkBuilt(b: BuiltMandate): Promise<void> {
  if (!b || b.version !== 1 || b.issuer !== SELF_ISSUER || typeof b.credential_id !== "string" || !ID.test(b.credential_id)) throw bad("not a mandate built by buildMandate");
  const agent = normalizeAgentKey(b.agent ?? {});
  if (agent.id !== b.agent.id) throw bad("agent is not in normalized form");
  if (b.principal?.kind === "company" && normalizeCnpj(b.principal.cnpj) !== b.principal.cnpj) throw bad("principal.cnpj is not in normalized form");
  if (b.principal?.kind !== "company" && b.principal?.kind !== "person") throw bad("principal.kind must be company or person");
  const m = validateMandate(b.mandate);
  if (canonicalize(m) !== canonicalize(b.mandate)) throw bad("mandate is not in normalized form");
  if ((await mandateSha256(b.mandate)) !== b.mandate_sha256) throw bad("mandate_sha256 does not match the mandate: it was changed after buildMandate");
  const issued = Date.parse(b.issued_at);
  const expires = Date.parse(b.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued) throw bad("bad issued_at / expires_at");
}

/**
 * The exact bytes the principal's ICP-Brasil certificate must sign: the KYA challenge text (company or person) with
 * issuer SELF_ISSUER, the credential id, the agent, the principal, the SHA-256 of the canonical mandate and the
 * expiry bound. The same text verifyPrincipalProof reads, built by the same function.
 */
export async function mandateSigningInput(b: BuiltMandate): Promise<SigningInput> {
  await checkBuilt(b);
  const base = { issuer: b.issuer, challenge_id: b.credential_id, agent: b.agent, mandate_sha256: b.mandate_sha256, expires_at: b.expires_at };
  const text = b.principal.kind === "company" ? challengeText({ ...base, cnpj: b.principal.cnpj }) : personChallengeText(base);
  const bytes = new TextEncoder().encode(text);
  return { text, bytes, sha256: hex(await crypto.subtle.digest("SHA-256", bytes)) };
}

const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")), (c) => c.charCodeAt(0));
const toArrayBuffer = (u: Uint8Array) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
const derOf = (c: Uint8Array | string) => (typeof c === "string" ? unb64(c) : c);

/**
 * The CMS with the given certificates added when it does not carry them already (signers that return only the
 * signature, or only the leaf). Certificates are outside what the signature covers, so adding them changes nothing
 * that was signed.
 */
export function withCertificates(cmsBase64: string, certChain: (Uint8Array | string)[]): string {
  let ci: pkijs.ContentInfo;
  let signed: pkijs.SignedData;
  try {
    ci = pkijs.ContentInfo.fromBER(toArrayBuffer(unb64(cmsBase64)));
    signed = new pkijs.SignedData({ schema: ci.content });
  } catch (e) {
    throw new KyaError("CHALLENGE_FAILED", `signature is not a CMS SignedData: ${(e as Error).message}`);
  }
  const have = (signed.certificates ?? []).filter((c): c is pkijs.Certificate => c instanceof pkijs.Certificate);
  const key = (c: pkijs.Certificate) => hex(c.toSchema().toBER(false));
  const seen = new Set(have.map(key));
  let added = 0;
  for (const raw of certChain) {
    let cert: pkijs.Certificate;
    try {
      cert = pkijs.Certificate.fromBER(toArrayBuffer(derOf(raw)));
    } catch (e) {
      throw bad(`certChain: not an X.509 certificate (DER or base64/PEM): ${(e as Error).message}`);
    }
    if (seen.has(key(cert))) continue;
    seen.add(key(cert));
    have.push(cert);
    added++;
  }
  if (!added) return cmsBase64.replace(/\s+/g, "");
  signed.certificates = have;
  const out = new pkijs.ContentInfo({ contentType: ci.contentType, content: signed.toSchema(true) });
  const der = new Uint8Array(out.toSchema().toBER(false));
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** "ACME LTDA" from "CN=ACME LTDA:11222333000181, O=ICP-Brasil, C=BR" (ICP-Brasil e-CNPJ convention; the CNPJ may be alphanumeric), else the CN. */
function legalNameOf(subject: string): string {
  const cn = /(?:^|,\s*)CN=([^,]+)/.exec(subject)?.[1]?.trim() ?? "";
  return cn.replace(/:[0-9A-Za-z]{12}\d{2}\s*$/, "").trim() || cn;
}

/**
 * Assembles the credential from the built mandate, the detached (or attached) CMS signature over
 * mandateSigningInput(b).text and the certificate chain (signer first; added to the CMS when missing). Verifies the
 * signature, the chain up to `anchors`, the CNPJ or the e-CPF, as a verifier will, and refuses (throws KyaError)
 * anything the verification would refuse. The certificate's revocation (CRL) stays with the caller, as in
 * verification: check it before handing the credential to the agent.
 *
 * Returns the credential in the /v1 format (issuer SELF_ISSUER, no issuer attestation: the principal's signature
 * is the proof) and the proof the agent presents with it (KYA-Principal-Proof, encodePrincipalProofHeader).
 */
export async function assembleCredential(b: BuiltMandate, signature: string, certChain: (Uint8Array | string)[], opts: { anchors: string[]; now: Date }): Promise<IssuedCredential> {
  const { text } = await mandateSigningInput(b);
  const now = requireDate(opts?.now, "opts.now");
  if (!Array.isArray(opts.anchors) || !opts.anchors.length) throw bad("opts.anchors: the ICP-Brasil trust anchors are required (the same a verifier uses)");
  if (typeof signature !== "string" || !signature.trim()) throw bad("signature: the CMS (base64 DER) is required");
  if (!Array.isArray(certChain)) throw bad("certChain must be an array (signer first); [] when the CMS already carries it");
  const cms = withCertificates(signature, certChain);
  const issuedAt = new Date(b.issued_at);
  const ttl_seconds = (Date.parse(b.expires_at) - issuedAt.getTime()) / 1000;
  let credential: Credential;
  if (b.principal.kind === "company") {
    const icp = await verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: b.principal.cnpj, anchors: opts.anchors, now });
    credential = buildCredential({
      credential_id: b.credential_id,
      agent: b.agent,
      cnpj: icp.cnpj,
      legal_name: legalNameOf(icp.certificate_subject),
      // Pure: nobody asked the Receita Federal. A verifier that needs it checks the CNPJ with its own source (D-24).
      registration_status: "NOT_CHECKED",
      certificate: { sha256: icp.certificate_sha256, subject: icp.certificate_subject, issuer: icp.issuer, signed_at: now.toISOString(), not_after: icp.not_after },
      mandate: b.mandate,
      mandate_sha256: b.mandate_sha256,
      ttl_seconds,
      issuer: SELF_ISSUER,
      now: issuedAt
    });
  } else {
    const icp = await verifyIcpPersonSignature({ cmsBase64: cms, challenge: text, anchors: opts.anchors, now });
    credential = buildPersonCredential({
      credential_id: b.credential_id,
      agent: b.agent,
      certificate: { sha256: icp.certificate_sha256, issuer: icp.issuer, signed_at: now.toISOString(), not_after: icp.not_after },
      mandate: b.mandate,
      mandate_sha256: b.mandate_sha256,
      ttl_seconds,
      issuer: SELF_ISSUER,
      now: issuedAt
    });
  }
  // No status service behind a self-issued credential: both URLs name the issuer, never a host to call.
  credential = { ...credential, verify_url: SELF_ISSUER, revocation_url: SELF_ISSUER };
  const issued: IssuedCredential = { credential, proof: { text, cms } };
  const check = await verifySelfIssuedCredential({ ...issued, anchors: opts.anchors, now });
  if (!check.ok) throw new KyaError("CHALLENGE_FAILED", `the assembled credential would not verify: ${check.checks.filter((c) => !c.ok).map((c) => `${c.rule}: ${c.detail}`).join("; ")}`);
  return issued;
}

export interface SelfIssuedCheck {
  rule: PrincipalProofCheck["rule"] | "credential" | "validity";
  ok: boolean;
  detail: string;
}

export interface SelfIssuedResult {
  ok: boolean;
  checks: SelfIssuedCheck[];
  /** For the caller's revocation check of the signing certificate (checkRevocation); null when the signature did not verify. */
  revocation: { serial_number: string; issuer_certificate: string | null; crl_urls: string[] } | null;
}

const lineOf = (text: string, key: string): string | null => {
  const lines = text.split("\n").filter((l) => l.startsWith(`${key}: `));
  return lines.length === 1 ? lines[0]!.slice(key.length + 2) : null;
};

/**
 * Verifies a credential issued by its principal, offline: every check of verifyPrincipalProof (signature and chain
 * to the anchors, certificate, agent, principal, issuer, mandate hash), plus what binds the credential's own fields
 * to the signed text: issuer SELF_ISSUER, the text's `challenge:` line is the credential id, the credential does not
 * outlive the text's `expires:` line, the mandate passes the schema, and the credential is in force at `now`.
 * Never throws on a bad credential. The certificate's revocation (CRL) is the caller's, with `revocation`.
 */
export async function verifySelfIssuedCredential(p: { credential: Credential; proof: PrincipalProof; anchors: string[]; now: Date }): Promise<SelfIssuedResult> {
  const checks: SelfIssuedCheck[] = [];
  const c = p.credential;
  if (!c || typeof c !== "object" || !c.agent || !c.principal || !c.authorized_by || !c.mandate) {
    return { ok: false, checks: [{ rule: "credential", ok: false, detail: "not a credential" }], revocation: null };
  }
  const base = await verifyPrincipalProof({ credential: c, proof: p.proof, anchors: p.anchors, now: p.now });
  checks.push(...base.checks);
  const text = typeof p.proof?.text === "string" ? p.proof.text : "";
  const problems: string[] = [];
  if (c.issuer !== SELF_ISSUER) problems.push(`issuer is ${c.issuer}, not ${SELF_ISSUER}`);
  if (c.version !== 1) problems.push("version is not 1");
  if (lineOf(text, "challenge") !== c.credential_id) problems.push("the signed text does not name this credential id");
  const method = isPersonPrincipal(c.principal) ? "icp-brasil-e-cpf" : "icp-brasil-e-cnpj";
  if (c.authorized_by.method !== method) problems.push(`authorized_by.method must be ${method}`);
  try {
    if (canonicalize(validateMandate(c.mandate)) !== canonicalize(c.mandate)) problems.push("mandate is not in normalized form");
  } catch (e) {
    problems.push((e as Error).message);
  }
  checks.push({ rule: "credential", ok: problems.length === 0, detail: problems.length ? problems.join("; ") : "self-issued credential bound to the signed text" });

  const signedBound = Date.parse(lineOf(text, "expires") ?? "");
  const expires = Date.parse(c.expires_at);
  const issued = Date.parse(c.issued_at);
  const now = p.now instanceof Date ? p.now.getTime() : Number.NaN;
  const validity: string[] = [];
  if (!Number.isFinite(signedBound)) validity.push("the signed text carries no expiry");
  else if (!Number.isFinite(expires) || expires > signedBound) validity.push("the credential outlives the expiry the principal signed");
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued >= expires) validity.push("bad issued_at / expires_at");
  else if (!Number.isFinite(now)) validity.push("the verifier's clock is not a valid date");
  else if (now < issued) validity.push(`not yet valid (issued ${c.issued_at})`);
  else if (effectiveStatus(c, new Date(now)) !== "active") validity.push(`credential is ${effectiveStatus(c, new Date(now))}`);
  checks.push({ rule: "validity", ok: validity.length === 0, detail: validity.length ? validity.join("; ") : `in force until ${c.expires_at}` });
  return { ok: checks.every((x) => x.ok), checks, revocation: base.revocation };
}

/** Who issues the next link: an issued credential (its agent delegates), or that credential and the chain so far. */
export interface DelegationParent {
  credential: DelegationAnchor & Partial<Pick<Credential, "status">>;
  chain?: Delegation[];
}

/**
 * Builds the mandate a (sub-)agent issues to the next key: the parent's agent (or the last delegate of `chain`) is
 * the issuer. Every risk field of the child mandate is required (as in buildMandate); the delegation is refused when
 * verification would refuse it: the parent may not delegate, the depth or lifetime exceeds its policy, the child
 * mandate is broader than the parent's (verifyDelegationChain's rules, through prepareDelegation), or the parent
 * credential is not in force at `now`. Returns the unsigned link and the text the delegator signs with its key.
 */
export async function buildDelegation(parent: DelegationParent, child: { delegate: { kind: unknown; id: unknown }; mandate: MandateTerms; ttl_seconds: number; now: Date }): Promise<{ delegation: Omit<Delegation, "signature">; text: string }> {
  if (!parent?.credential) throw bad("parent.credential is required");
  if (!child || typeof child !== "object") throw bad("child must be an object");
  const now = requireDate(child.now);
  const credential = parent.credential;
  if (credential.status !== undefined && credential.status !== "active") throw bad(`the parent credential is ${credential.status}`);
  const end = Date.parse(credential.expires_at);
  if (!Number.isFinite(end) || end <= now.getTime()) throw bad("the parent credential is not in force at now");
  for (const link of parent.chain ?? []) if (Date.parse(link.expires_at) <= now.getTime()) throw bad("a link of the parent chain has expired");
  const mandate = requireMandateTerms(child.mandate, "child.mandate");
  if (typeof child.ttl_seconds !== "number") throw bad("child.ttl_seconds is required (the delegation lifetime is the delegator's decision)");
  return prepareDelegation({ credential, chain: parent.chain, delegate: child.delegate, mandate, ttlSeconds: child.ttl_seconds, now });
}

/**
 * Joins the delegator's signature (EIP-191 for evm, raw Ed25519 base64url for web-bot-auth) to a link from
 * buildDelegation and returns the whole chain, after checking it with verifyDelegationChain at `now`: a wrong key or
 * a changed link is refused here, not at the verifier.
 */
export async function assembleDelegation(parent: DelegationParent, prepared: { delegation: Omit<Delegation, "signature"> }, signature: string, now: Date): Promise<Delegation[]> {
  requireDate(now);
  if (typeof signature !== "string" || !signature) throw bad("signature is required");
  const chain = [...(parent.chain ?? []), { ...prepared.delegation, signature } as Delegation];
  const r = await verifyDelegationChain({ credential: parent.credential, chain, now });
  if (!r.ok) throw bad(`the delegation would not verify: ${r.error}: ${r.message}`);
  return chain;
}
