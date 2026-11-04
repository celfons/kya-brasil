/// <reference types="node" /> // test-only: Buffer
/**
 * Sign in with KYA without the issuer (offline option): the agent sends its credential and the principal's proof,
 * the middleware checks them against a throwaway ICP-Brasil test chain and a CRL the caller supplies, and never
 * calls fetch. Never real certificates.
 */
import "reflect-metadata";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { privateKeyToAccount } from "viem/accounts";
import {
  type Delegation,
  type MandateTerms,
  OID_ICP_CNPJ,
  SELF_ISSUER,
  assembleCredential,
  buildCredential,
  buildMandate,
  challengeText,
  checkRevocation,
  delegationText,
  ecnpjSigner,
  evidenceFromRevocation,
  generateAttestationKey,
  importPrivateKey,
  mandateSha256,
  mandateSigningInput,
  signAttestation,
  validateMandate,
  verifyIcpSignature
} from "@kya-brasil/core";
import { type KyaOfflineOptions, KYA_HEADERS, createKyaAuth, signDelegation, signRequest } from "./auth";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const CNPJ = "11222333000181";
const NOW = new Date("2026-11-04T12:00:00Z");
const AGENT_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const OTHER_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const AGENT = privateKeyToAccount(AGENT_PK).address;
const SUB = privateKeyToAccount(OTHER_PK).address;
const URL_ = "https://shop.beta.com.br/orders";
const SUB_MANDATE = { actions: ["order"], max_per_day: { amount: 300, currency: "BRL" }, currencies: ["BRL"], counterparties: ["shop.beta.com.br"], valid_from: "2026-11-01T00:00:00Z", valid_until: "2027-03-01T00:00:00Z" };

async function ca(name = "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR") {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name, notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  return { keys, cert };
}

async function leaf(root: Awaited<ReturnType<typeof ca>>) {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const other = new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(CNPJ))) });
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: "02", subject: `CN=ACME LTDA:${CNPJ}, O=ICP-Brasil, C=BR`, issuer: root.cert.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: root.keys.privateKey, extensions: [san] });
  return { keys, cert };
}

const terms = (over: Partial<MandateTerms> = {}): MandateTerms => ({
  actions: ["quote", "order", "pay"],
  max_per_operation: { amount: 5000, currency: "BRL" },
  max_per_day: { amount: 20000, currency: "BRL" },
  currencies: ["BRL"],
  counterparties: ["*.beta.com.br"],
  payment_instruments: [],
  valid_from: "2026-11-01T00:00:00Z",
  valid_until: "2027-03-01T00:00:00Z",
  delegation: { max_depth: 2, max_ttl_seconds: 3600 },
  ...over
});

let pkiCache: Promise<Awaited<ReturnType<typeof setup>>> | null = null;
async function setup() {
  const root = await ca();
  const company = await leaf(root);
  const signer = ecnpjSigner({ certificates: [new Uint8Array(company.cert.rawData), new Uint8Array(root.cert.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", company.keys.privateKey, d.slice().buffer as ArrayBuffer)) });
  const anchors = [b64(root.cert.rawData)];
  // The principal issues the credential itself (D-37), with its e-CNPJ.
  const built = await buildMandate({ credential_id: "cred-0001", agent: { kind: "evm", id: AGENT }, principal: { kind: "company", cnpj: CNPJ }, mandate: terms(), ttl_seconds: 30 * 86400, now: NOW });
  const self = await assembleCredential(built, await signer.sign((await mandateSigningInput(built)).text), [], { anchors, now: NOW });
  const crl = async (entries: x509.X509CrlEntryParams[]) => (await x509.X509CrlGenerator.create({ issuer: root.cert.subject, thisUpdate: new Date(NOW.getTime() - 3 * 3600_000), nextUpdate: new Date(NOW.getTime() + 86400_000), signingAlgorithm: alg, signingKey: root.keys.privateKey, entries })).rawData;
  return { root, company, signer, anchors, self, cleanCrl: await crl([]), revokedCrl: await crl([{ serialNumber: "02", revocationDate: new Date(NOW.getTime() - 4 * 3600_000), reason: x509.X509CrlReason.keyCompromise }]) };
}
const pki = () => (pkiCache ??= setup());

/** The caller's certificate status: a CRL it fetched (here, in memory), checked by the core. */
const crlStatus = (crlDer: ArrayBuffer, anchors: string[]): KyaOfflineOptions["certificateStatus"] => async ({ revocation }) =>
  evidenceFromRevocation(await checkRevocation({ crlDer, serial: revocation.serial_number, issuerCertificate: revocation.issuer_certificate ?? anchors[0]!, pastNextUpdate: "refuse", now: NOW }), "CRL of AC Teste");

let fetchSpy: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchSpy = vi.fn(async () => new Response("{}", { status: 500 }));
  vi.stubGlobal("fetch", fetchSpy);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

async function offlineAuth(over: Partial<KyaOfflineOptions> = {}) {
  const k = await pki();
  return createKyaAuth({ baseUrl: "https://kya.test", fetch: fetchSpy as unknown as typeof fetch, offline: { anchors: k.anchors, now: () => NOW, certificateStatus: crlStatus(k.cleanCrl, k.anchors), ...over } });
}

async function presented(p: { credential?: object; key?: `0x${string}`; delegation?: Delegation[]; now?: Date; body?: string } = {}) {
  const k = await pki();
  const credential = p.credential ?? k.self.credential;
  const headers = await signRequest({ credentialId: (credential as { credential_id: string }).credential_id, key: { kind: "evm", privateKey: p.key ?? AGENT_PK }, method: "POST", url: URL_, body: p.body ?? '{"sku":"A1"}', now: p.now ?? NOW, delegation: p.delegation, present: { credential, proof: k.self.proof } });
  return new Request(URL_, { method: "POST", headers, body: p.body ?? '{"sku":"A1"}' });
}

describe("Sign in with KYA offline: self-issued credential", () => {
  it("accepts the request with no call to fetch and evaluates the mandate locally", async () => {
    const auth = await offlineAuth();
    const r = await auth.authenticate(await presented());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.kya.offline).toMatchObject({ issuer: SELF_ISSUER, self_issued: true, verified_at: NOW.toISOString() });
    expect(r.kya.offline?.evidence[0]).toMatchObject({ kind: "certificate", in_force: true });
    expect(r.kya.principal).toMatchObject({ cnpj: CNPJ, legal_name: "ACME LTDA" });
    expect(r.kya.signer).toBe(AGENT);
    expect(r.kya.body).toBe("verified");
    expect(r.kya.check({ action: "order", amount: 4200, currency: "BRL", counterparty: "shop.beta.com.br" }).allowed).toBe(true);
    // An action outside the mandate: not in actions, above the ceiling, another counterparty.
    expect(r.kya.check({ action: "sign" }).allowed).toBe(false);
    expect(r.kya.check({ action: "pay", amount: 8000, currency: "BRL" }).allowed).toBe(false);
    expect(r.kya.check({ action: "pay", amount: 10, currency: "BRL", counterparty: "evil.com" }).allowed).toBe(false);
    const verdict = await r.kya.allowed({ action: "pay", amount: 8000, currency: "BRL" });
    expect(verdict).toMatchObject({ allowed: false, offline: true });
    expect((await r.kya.allowed({ action: "quote" })).allowed).toBe(true);
    // Adapters too.
    const handler = auth.fetchHandler(async (_r, kya) => new Response(kya.credential_id));
    expect(await (await handler(await presented())).text()).toBe("cred-0001");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses a tampered mandate, a wrong agent key and a missing proof or credential", async () => {
    const k = await pki();
    const auth = await offlineAuth();
    const tampered = { ...k.self.credential, mandate: { ...k.self.credential.mandate, max_per_operation: { amount: 999999, currency: "BRL" } } };
    expect(await auth.authenticate(await presented({ credential: tampered }))).toMatchObject({ ok: false, status: 401, error: "KYA_PRINCIPAL_PROOF_INVALID" });
    expect(await auth.authenticate(await presented({ key: OTHER_PK }))).toMatchObject({ ok: false, status: 401, error: "KYA_BAD_SIGNATURE" });

    const req = await presented();
    const noProof = new Headers(req.headers);
    noProof.delete(KYA_HEADERS.principalProof);
    expect(await auth.authenticate(new Request(URL_, { method: "POST", headers: noProof, body: '{"sku":"A1"}' }))).toMatchObject({ ok: false, status: 401, error: "KYA_PRINCIPAL_PROOF_MISSING" });
    const plain = await signRequest({ credentialId: "cred-0001", key: { kind: "evm", privateKey: AGENT_PK }, method: "GET", url: URL_, now: NOW });
    expect(await auth.authenticate(new Request(URL_, { headers: plain }))).toMatchObject({ ok: false, status: 401, error: "KYA_CREDENTIAL_MISSING" });
    const garbage = new Headers(req.headers);
    garbage.set(KYA_HEADERS.principalProof, "!!");
    expect(await auth.authenticate(new Request(URL_, { method: "POST", headers: garbage, body: '{"sku":"A1"}' }))).toMatchObject({ ok: false, error: "KYA_PRINCIPAL_PROOF_MALFORMED" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses untrusted anchors, an expired credential and a revoked certificate", async () => {
    const k = await pki();
    const stranger = await ca("CN=Outra AC, O=Teste, C=BR");
    const untrusted = await offlineAuth({ anchors: [b64(stranger.cert.rawData)] });
    const r = await untrusted.authenticate(await presented());
    expect(r).toMatchObject({ ok: false, status: 401, error: "KYA_PRINCIPAL_PROOF_INVALID" });
    if (!r.ok) expect(r.message).toMatch(/^signature:/);

    const later = new Date(Date.parse(k.self.credential.expires_at) + 3600_000);
    const expired = await offlineAuth({ now: () => later, certificateStatus: () => ({ kind: "certificate", in_force: true, as_of: later.toISOString() }) });
    expect(await expired.authenticate(await presented({ now: later }))).toMatchObject({ ok: false, status: 403, error: "KYA_CREDENTIAL_NOT_ACTIVE" });

    const revoked = await offlineAuth({ certificateStatus: crlStatus(k.revokedCrl, k.anchors) });
    const rr = await revoked.authenticate(await presented());
    expect(rr).toMatchObject({ ok: false, status: 403, error: "KYA_CERTIFICATE_REVOKED" });
    if (!rr.ok) expect(rr.message).toContain("keyCompromise");

    const down = await offlineAuth({ certificateStatus: () => { throw new Error("CRL unreachable"); } });
    expect(await down.authenticate(await presented())).toMatchObject({ ok: false, status: 502, error: "KYA_CERTIFICATE_STATUS_UNAVAILABLE" });
    const none = await offlineAuth({ certificateStatus: () => [] });
    expect(await none.authenticate(await presented())).toMatchObject({ ok: false, status: 403, error: "KYA_CERTIFICATE_STATUS_UNKNOWN" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("verifies a delegation chain offline and refuses one broader than its parent", async () => {
    const k = await pki();
    const auth = await offlineAuth();
    const chain = await signDelegation({ credential: k.self.credential, key: { kind: "evm", privateKey: AGENT_PK }, delegate: { kind: "evm", id: SUB }, mandate: { ...SUB_MANDATE, max_per_operation: { amount: 100, currency: "BRL" } }, ttlSeconds: 600, now: NOW });
    const r = await auth.authenticate(await presented({ key: OTHER_PK, delegation: chain }));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.kya.signer).toBe(SUB);
    expect(r.kya.delegation?.depth).toBe(1);
    expect(r.kya.check({ action: "order", amount: 90, currency: "BRL", counterparty: "shop.beta.com.br" }).allowed).toBe(true);
    // Inside the credential's mandate, outside the delegate's.
    expect(r.kya.check({ action: "order", amount: 400, currency: "BRL", counterparty: "shop.beta.com.br" }).allowed).toBe(false);
    expect(r.kya.check({ action: "pay", amount: 10, currency: "BRL" }).allowed).toBe(false);
    // The parent key cannot sign on the delegate's behalf.
    expect(await auth.authenticate(await presented({ delegation: chain }))).toMatchObject({ ok: false, error: "KYA_BAD_SIGNATURE" });

    // A link signed by the agent but broader than the credential's mandate (signDelegation would refuse it).
    const link = { credential_id: "cred-0001", parent: null, delegate: { kind: "evm" as const, id: SUB }, depth: 1, issued_at: NOW.toISOString(), expires_at: new Date(NOW.getTime() + 600_000).toISOString(), mandate: validateMandate({ ...SUB_MANDATE, max_per_operation: { amount: 9000, currency: "BRL" } }) };
    const broader: Delegation[] = [{ version: 1, ...link, signature: await privateKeyToAccount(AGENT_PK).signMessage({ message: await delegationText(link) }) } as Delegation];
    expect(await auth.authenticate(await presented({ key: OTHER_PK, delegation: broader }))).toMatchObject({ ok: false, status: 403, error: "KYA_DELEGATION_BROADER" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("applies the caller's freshness policy to each action (checkFreshAction)", async () => {
    // CRL 3 h old. L = 100 BRL, λ = 0.01/h: 5000 BRL allows 2 h, 100 BRL the 1-day ceiling.
    const auth = await offlineAuth({ freshness: { max_expected_loss: { amount: 100, currency: "BRL" }, revocation_rate_per_hour: { certificate: 0.01 }, require: ["certificate"], max_age_seconds: 86400, max_clock_skew_seconds: 60, unvalued_action: "refuse", past_valid_until: "refuse" } });
    const r = await auth.authenticate(await presented());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const small = r.kya.check({ action: "pay", amount: 100, currency: "BRL" });
    expect(small.allowed).toBe(true);
    expect(small.freshness?.ok).toBe(true);
    const large = r.kya.check({ action: "pay", amount: 5000, currency: "BRL" });
    expect(large.allowed).toBe(false);
    expect(large.freshness?.refresh).toEqual(["certificate"]);
    expect(large.checks.find((c) => c.rule === "freshness (certificate)")?.ok).toBe(false);
    expect(r.kya.check({ action: "quote" }).allowed).toBe(false); // unvalued action, refused by the policy
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("Sign in with KYA offline: issuer-issued credential with the principal's proof", () => {
  const ISSUER = "https://issuer.test";
  async function issuerIssued() {
    const k = await pki();
    const mandate = validateMandate({ actions: ["order"], max_per_operation: { amount: 1000, currency: "BRL" }, currencies: ["BRL"] });
    const mandate_sha256 = await mandateSha256(mandate);
    const text = challengeText({ issuer: ISSUER, challenge_id: "ch-1", agent: { kind: "evm", id: AGENT }, cnpj: CNPJ, mandate_sha256, expires_at: new Date(NOW.getTime() + 900_000).toISOString() });
    const cms = await k.signer.sign(text);
    const icp = await verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: CNPJ, anchors: k.anchors, now: NOW });
    const credential = buildCredential({ credential_id: "6d0b1c2e-1111-4222-8333-444455556666", agent: { kind: "evm", id: AGENT }, cnpj: CNPJ, legal_name: "ACME LTDA", registration_status: "ATIVA", certificate: { sha256: icp.certificate_sha256, subject: icp.certificate_subject, issuer: icp.issuer, signed_at: NOW.toISOString(), not_after: icp.not_after }, mandate, mandate_sha256, ttl_seconds: 90 * 86400, issuer: ISSUER, now: NOW });
    const key = await generateAttestationKey();
    const attestation = await signAttestation(credential as unknown as Record<string, unknown>, await importPrivateKey(key.privateKeyPkcs8), key.keyId, credential.verify_url, NOW);
    return { k, credential: { ...credential, attestation }, proof: { text, cms }, jwk: key.publicJwk };
  }
  const request = async (credential: { credential_id: string }, proof: { text: string; cms: string }) =>
    new Request(URL_, { headers: await signRequest({ credentialId: credential.credential_id, key: { kind: "evm", privateKey: AGENT_PK }, method: "GET", url: URL_, now: NOW, present: { credential, proof } }) });

  it("accepts it with the issuer's public key and the proof, without calling the issuer", async () => {
    const { credential, proof, jwk } = await issuerIssued();
    const auth = await offlineAuth({ issuerKeys: { [ISSUER]: jwk } });
    const r = await auth.authenticate(await request(credential, proof));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.kya.offline).toMatchObject({ issuer: ISSUER, self_issued: false });
    expect(r.kya.check({ action: "order", amount: 900, currency: "BRL" }).allowed).toBe(true);
    expect(r.kya.check({ action: "order", amount: 1100, currency: "BRL" }).allowed).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses an issuer it does not list and a credential edited after the issuer signed it", async () => {
    const { credential, proof, jwk } = await issuerIssued();
    expect(await (await offlineAuth()).authenticate(await request(credential, proof))).toMatchObject({ ok: false, status: 401, error: "KYA_ISSUER_NOT_TRUSTED" });
    const auth = await offlineAuth({ issuerKeys: { [ISSUER]: jwk } });
    const extended = { ...credential, expires_at: "2030-01-01T00:00:00.000Z" };
    expect(await auth.authenticate(await request(extended, proof))).toMatchObject({ ok: false, status: 401, error: "KYA_CREDENTIAL_SIGNATURE_INVALID" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("Sign in with KYA offline: configuration", () => {
  it("throws at construction when offline mode lacks what it needs", async () => {
    const k = await pki();
    const ok: KyaOfflineOptions = { anchors: k.anchors, now: () => NOW, certificateStatus: () => [] };
    expect(() => createKyaAuth({ offline: { ...ok, anchors: [] } })).toThrow(/anchors/);
    expect(() => createKyaAuth({ offline: { ...ok, now: undefined as unknown as () => Date } })).toThrow(/clock/);
    expect(() => createKyaAuth({ offline: { ...ok, certificateStatus: undefined as unknown as KyaOfflineOptions["certificateStatus"] } })).toThrow(/certificateStatus/);
    expect(() => createKyaAuth({ offline: { ...ok, freshness: { max_expected_loss: { amount: 100, currency: "BRL" } } as never } })).toThrow(/freshness policy/);
    expect(() => createKyaAuth({ offline: ok })).not.toThrow();
  });

  it("with issuerFallback, a request without the credential goes to the issuer as before", async () => {
    const issuerFetch = vi.fn(async () => new Response(JSON.stringify({ credential_id: "c-1", status: "active", status_reason: null, agent: { kind: "evm", id: AGENT }, principal: { cnpj: CNPJ, legal_name: "ACME LTDA" }, credential: { mandate: { actions: ["order"] }, expires_at: "2099-01-01T00:00:00Z" }, events: [] })));
    const k = await pki();
    const auth = createKyaAuth({ baseUrl: "https://kya.test", fetch: issuerFetch as unknown as typeof fetch, offline: { anchors: k.anchors, now: () => NOW, certificateStatus: crlStatus(k.cleanCrl, k.anchors), issuerFallback: true } });
    const headers = await signRequest({ credentialId: "c-1", key: { kind: "evm", privateKey: AGENT_PK }, method: "GET", url: URL_ }); // the issuer path keeps the system clock
    const r = await auth.authenticate(new Request(URL_, { headers }));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.kya.offline).toBeUndefined();
    expect(issuerFetch).toHaveBeenCalledTimes(1);
    expect((await auth.authenticate(await presented())).ok).toBe(true); // still offline when the credential comes along
    expect(issuerFetch).toHaveBeenCalledTimes(1);
  });
});
