/**
 * Natural persons as principals (D-29). What the issuer keeps: HMAC(key, CPF) and its key version while the
 * credential is alive, plus the log of "does this CPF match" checks; never the name, the CPF or the
 * certificate subject. What it publishes: nothing personal. What a verifier gets: whether a CPF it already has
 * matches (paid, limited to 3 non-matching answers per credential and verifier), and a subject reference of its
 * own for that person. The person sees every check in their inventory, signed with their e-CPF.
 */
import {
  type AgentKey, KyaError, type Mandate, buildPersonCredential, normalizeCpf, newPersonChallenge, personHash, personKeys, signCredential, subjectRef, verifyIcpPersonSignature
} from "@kya-brasil/core";
import { icpAnchors } from "./anchors";
import { material, signAnswer } from "./attest";
import type { AppEnv } from "./env";
import { certificateRevocation } from "./revocation";
import { Store, type AgentRow } from "./store";

const MAX_NEGATIVE_CHECKS = 3;
const INVENTORY_WINDOW_MS = 10 * 60_000;

/** The keys, or a clear refusal: without them this issuer offers no person credentials (fail closed). */
export function keysOf(env: AppEnv) {
  const k = personKeys(env.PERSON_HMAC_KEYS);
  if (!k) throw new KyaError("UPSTREAM_ERROR", "this issuer does not offer credentials for natural persons (no PERSON_HMAC_KEYS configured)");
  return k;
}

const keyFor = (env: AppEnv, version: number) => {
  const key = keysOf(env).all.get(version);
  if (!key) throw new KyaError("UPSTREAM_ERROR", `person key version ${version} is no longer configured`);
  return key;
};

/** Constant-time comparison of two base64url hashes. */
function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export function personChallenge(issuer: string, agent: AgentKey) {
  return newPersonChallenge({ issuer, agent });
}

/** Issuance or renewal for a person: e-CPF proof, CRL, keyed hash; a renewal must be signed by the same person. */
export async function issuePerson(env: AppEnv, issuer: string, row: AgentRow, agent: AgentKey, text: string, ecpfSignature: string, event: "issued" | "renewed", mandate: Mandate) {
  const store = new Store(env.DB);
  const keys = keysOf(env);
  const anchors = await icpAnchors(env);
  const icp = await verifyIcpPersonSignature({ cmsBase64: ecpfSignature, challenge: text, anchors });
  const revocation = await certificateRevocation(env, icp);
  if (revocation.revoked) throw new KyaError("CERTIFICATE_REVOKED", `the e-CPF certificate was revoked by its AC on ${revocation.revoked_at}${revocation.reason ? ` (${revocation.reason})` : ""}`);
  if (row.person_hash && row.person_key_version) {
    const previous = await personHash(keyFor(env, row.person_key_version), icp.cpf);
    if (!same(previous, row.person_hash)) throw new KyaError("CHALLENGE_FAILED", "this credential belongs to another person; only the same e-CPF holder can renew it");
  }
  const hash = await personHash(keys.current.key, icp.cpf);
  const m = await material(env);
  if (!m) throw new KyaError("UPSTREAM_ERROR", "issuer has no signing key");
  const certificate = { sha256: icp.certificate_sha256, issuer: icp.issuer, signed_at: icp.signed_at };
  const credential = await signCredential(buildPersonCredential({ credential_id: row.id, agent, certificate, mandate, issuer }), m.key, m.keyId);
  // No subject, no name: the certificate record keeps only what the CRL checks need.
  const record = { sha256: icp.certificate_sha256, subject: "", issuer: icp.issuer, signed_at: icp.signed_at, serial_number: icp.serial_number, issuer_certificate: icp.issuer_certificate, crl_urls: icp.crl_urls, revocation_checked_at: new Date().toISOString() };
  await store.issue({ id: row.id, legal_name: "", credential, certificate: record, mandate, event });
  await store.setPersonHash(row.id, hash, keys.current.version);
  return { credential, warnings: [] as string[], kyb_warnings: [] as string[] };
}

/** Revocation by the person: the e-CPF that signs the revocation text must be the one behind the credential. */
export async function revokePerson(env: AppEnv, row: AgentRow, signedText: string, signature: string, reason: string) {
  const store = new Store(env.DB);
  const icp = await verifyIcpPersonSignature({ cmsBase64: signature, challenge: signedText, anchors: await icpAnchors(env) });
  if (!row.person_hash || !row.person_key_version) throw new KyaError("CONFLICT", "this credential has no person data left (revoked or expired)");
  if (!same(await personHash(keyFor(env, row.person_key_version), icp.cpf), row.person_hash)) throw new KyaError("CHALLENGE_FAILED", "this e-CPF is not the one behind the credential");
  await store.setStatus({ id: row.id, status: "revoked", reason, actor: "company" });
  await store.clearPerson(row.id);
  return { credential_id: row.id, status: "revoked", reason, revoked_at: new Date().toISOString() };
}

/**
 * kya_principal_match: does this CPF match the person behind the credential? Signed answer; on a match, the
 * verifier's own subject reference for that person. The CPF given is used for the comparison only, never stored.
 */
export async function principalMatch(env: AppEnv, origin: string, id: string, body: { cpf?: unknown }, verifier: string) {
  const store = new Store(env.DB);
  const row = await store.get(id);
  if (!row) throw new KyaError("NOT_FOUND", "unknown credential_id");
  if (row.principal_kind !== "person") throw new KyaError("INVALID_INPUT", "this credential belongs to a company; its CNPJ is in the credential itself");
  const live = (row.status === "active" || row.status === "suspended") && !!row.expires_at && Date.parse(row.expires_at) > Date.now();
  if (!live || !row.person_hash || !row.person_key_version) throw new KyaError("NOT_FOUND", "no person data for this credential (not issued yet, revoked or expired)");
  if (typeof body.cpf !== "string") throw new KyaError("INVALID_INPUT", "cpf is required");
  const cpf = normalizeCpf(body.cpf);
  const who = verifier.toLowerCase();
  if ((await store.negativePersonChecks(row.id, who)) >= MAX_NEGATIVE_CHECKS) throw new KyaError("RATE_LIMITED", `this verifier already got ${MAX_NEGATIVE_CHECKS} non-matching answers for this credential; no more checks`);
  const key = keyFor(env, row.person_key_version);
  const match = same(await personHash(key, cpf), row.person_hash);
  await store.recordPersonCheck(row.id, who, match);
  const out: Record<string, unknown> = {
    credential_id: row.id,
    match,
    ...(match ? { subject_ref: await subjectRef(key, row.person_hash, who) } : {}),
    verifier: who,
    status: row.status,
    checked_at: new Date().toISOString()
  };
  const attestation = await signAnswer(env, out, origin);
  return attestation ? { ...out, attestation } : out;
}

/** The person's own view: every credential behind their e-CPF and every check made against each one. */
export async function personAgents(env: AppEnv, body: { signed_text?: unknown; ecpf_signature?: unknown }) {
  if (typeof body.signed_text !== "string" || typeof body.ecpf_signature !== "string") throw new KyaError("INVALID_INPUT", "signed_text and ecpf_signature are required");
  const m = /^KYA Brasil: my agents\nat: (\S+)$/.exec(body.signed_text);
  const at = m ? Date.parse(m[1]!) : NaN;
  if (!m || Number.isNaN(at)) throw new KyaError("INVALID_INPUT", 'signed_text must be "KYA Brasil: my agents\\nat: <ISO time>"');
  if (Math.abs(Date.now() - at) > INVENTORY_WINDOW_MS) throw new KyaError("CHALLENGE_FAILED", "signed_text is older than 10 minutes (or in the future); sign a fresh one");
  const icp = await verifyIcpPersonSignature({ cmsBase64: body.ecpf_signature, challenge: body.signed_text, anchors: await icpAnchors(env) });
  const keys = keysOf(env);
  const hashes = await Promise.all([...keys.all.entries()].map(async ([version, key]) => ({ version, hash: await personHash(key, icp.cpf) })));
  const store = new Store(env.DB);
  const rows = await store.byPersonHashes(hashes);
  return {
    agents: await Promise.all(
      rows.map(async (r) => ({
        credential_id: r.id,
        agent: { kind: r.agent_kind, id: r.agent_id },
        status: r.status,
        issued_at: r.issued_at,
        expires_at: r.expires_at,
        checks: (await store.personChecks(r.id)).map((c) => ({ verifier: c.verifier, matched: c.matched === 1, at: c.ts }))
      }))
    ),
    note: "Only live credentials are listed: person data is deleted when a credential is revoked or expires."
  };
}
