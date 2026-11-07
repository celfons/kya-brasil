/// <reference types="node" /> // test-only: Buffer
/**
 * Offline verification with `companyWill` (SPEC section 21): the HTTP verifier accepts a self-issued company
 * credential only when a legal representative co-signed it. Throwaway ICP-Brasil test chain, never real certificates.
 */
import "reflect-metadata";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { privateKeyToAccount } from "viem/accounts";
import { OID_ICP_CNPJ, OID_ICP_PERSON, OID_ICP_RESPONSIBLE, addCosignature, assembleCredential, buildMandate, checkRevocation, ecnpjSigner, encodePrincipalProofHeader, evidenceFromRevocation, mandateSigningInput } from "@kya-brasil/core";
import { type KyaOfflineOptions, KYA_HEADERS, createKyaAuth, signRequest } from "./auth";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const CNPJ = "11222333000181";
const REP = "52998224725";
const OTHER = "11144477735";
const NOW = new Date("2026-11-04T12:00:00Z");
const AGENT_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const AGENT = privateKeyToAccount(AGENT_PK).address;
const URL_ = "https://shop.beta.com.br/orders";

type Pair = { keys: CryptoKeyPair; cert: x509.X509Certificate };
async function ca(): Promise<Pair> {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  return { keys, cert };
}
async function leaf(root: Pair, who: { cnpj?: string; cpf?: string; responsible?: string }, serial: string): Promise<Pair> {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const on = (typeId: string, v: string) => new OtherName({ typeId, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(v))) });
  const others = who.cpf ? [on(OID_ICP_PERSON, `01011990${who.cpf}00000000000000000000000000000`)] : [on(OID_ICP_CNPJ, who.cnpj!), ...(who.responsible ? [on(OID_ICP_RESPONSIBLE, `01011980${who.responsible}00000000000000000000000000000`)] : [])];
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames(others.map((o) => new GeneralName({ otherName: o })))));
  const subject = who.cpf ? `CN=FULANO DE TAL:${who.cpf}, O=ICP-Brasil, C=BR` : `CN=ACME LTDA:${who.cnpj}, O=ICP-Brasil, C=BR`;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: serial, subject, issuer: root.cert.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: root.keys.privateKey, extensions: [san, new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true)] });
  return { keys, cert };
}
const signerOf = (l: Pair, root: Pair) => ecnpjSigner({ certificates: [new Uint8Array(l.cert.rawData), new Uint8Array(root.cert.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", l.keys.privateKey, d.slice().buffer as ArrayBuffer)) });

async function setup() {
  const root = await ca();
  const company = await leaf(root, { cnpj: CNPJ, responsible: REP }, "02");
  const rep = await leaf(root, { cpf: REP }, "03");
  const other = await leaf(root, { cpf: OTHER }, "04");
  const anchors = [b64(root.cert.rawData)];
  const built = await buildMandate({ credential_id: "cred-cw-1", agent: { kind: "evm", id: AGENT }, principal: { kind: "company", cnpj: CNPJ }, mandate: { actions: ["order"], max_per_operation: { amount: 5000, currency: "BRL" }, max_per_day: { amount: 20000, currency: "BRL" }, currencies: ["BRL"], counterparties: ["*.beta.com.br"], payment_instruments: [], valid_from: "2026-11-01T00:00:00Z", valid_until: "2027-03-01T00:00:00Z", delegation: null }, ttl_seconds: 30 * 86400, now: NOW });
  const { text } = await mandateSigningInput(built);
  const plain = await assembleCredential(built, await signerOf(company, root).sign(text), [], { anchors, now: NOW });
  const byRep = await addCosignature(plain, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
  const byOther = await addCosignature(plain, await signerOf(other, root).sign(text), [], { anchors, now: NOW });
  const crl = (await x509.X509CrlGenerator.create({ issuer: root.cert.subject, thisUpdate: new Date(NOW.getTime() - 3600_000), nextUpdate: new Date(NOW.getTime() + 86400_000), signingAlgorithm: alg, signingKey: root.keys.privateKey, entries: [] })).rawData;
  return { anchors, plain, byRep, byOther, crl };
}
let cache: ReturnType<typeof setup> | null = null;
const k = () => (cache ??= setup());

beforeEach(() => vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 500 }))));
afterEach(() => vi.unstubAllGlobals());

async function auth(companyWill?: KyaOfflineOptions["companyWill"]) {
  const { anchors, crl } = await k();
  const certificateStatus: KyaOfflineOptions["certificateStatus"] = async ({ revocation }) => evidenceFromRevocation(await checkRevocation({ crlDer: crl, serial: revocation.serial_number, issuerCertificate: revocation.issuer_certificate ?? anchors[0]!, pastNextUpdate: "refuse", now: NOW }), "CRL");
  return createKyaAuth({ baseUrl: "https://kya.test", fetch: globalThis.fetch, offline: { anchors, now: () => NOW, certificateStatus, ...(companyWill ? { companyWill } : {}) } });
}
async function request(issued: Awaited<ReturnType<typeof setup>>["plain"]) {
  const headers = await signRequest({ credentialId: issued.credential.credential_id, key: { kind: "evm", privateKey: AGENT_PK }, method: "POST", url: URL_, body: "{}", now: NOW, present: { credential: issued.credential, proof: issued.proof } });
  expect(headers[KYA_HEADERS.principalProof]).toBeTruthy();
  return new Request(URL_, { method: "POST", headers, body: "{}" });
}

describe("offline verification with companyWill (section 21)", () => {
  it("without the option, the e-CNPJ alone is enough, with or without co-signature", async () => {
    const { plain, byRep } = await k();
    const a = await auth();
    expect((await a.authenticate(await request(plain))).ok).toBe(true);
    expect((await a.authenticate(await request(byRep))).ok).toBe(true);
  });

  it("with a representatives list: accepts the representative's co-signature, refuses none and a stranger's", async () => {
    const { plain, byRep, byOther } = await k();
    const a = await auth({ representatives: () => [REP] });
    expect((await a.authenticate(await request(byRep))).ok).toBe(true);
    expect(await a.authenticate(await request(plain))).toMatchObject({ ok: false, status: 403, error: "KYA_COMPANY_WILL_REQUIRED", message: expect.stringMatching(/NO_COSIGNATURE/) });
    expect(await a.authenticate(await request(byOther))).toMatchObject({ ok: false, status: 403, error: "KYA_COMPANY_WILL_REQUIRED", message: expect.stringMatching(/COSIGNER_NOT_REPRESENTATIVE/) });
  });

  it("with acceptCertificateResponsible and no list: the responsible named in the e-CNPJ counts", async () => {
    const { byRep, byOther } = await k();
    const a = await auth({ acceptCertificateResponsible: true });
    expect((await a.authenticate(await request(byRep))).ok).toBe(true);
    expect(await a.authenticate(await request(byOther))).toMatchObject({ ok: false, error: "KYA_COMPANY_WILL_REQUIRED" });
  });

  it("refuses an option with no source of representatives", async () => {
    const { anchors } = await k();
    expect(() => createKyaAuth({ baseUrl: "https://kya.test", offline: { anchors, now: () => NOW, certificateStatus: async () => [], companyWill: {} } })).toThrow(/representatives/);
  });
});
