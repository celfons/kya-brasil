/// <reference types="node" /> // test-only: Buffer, node:fs
/**
 * Adversarial vectors (H4), certificate part: the cases the Alloy model cannot produce, because they are about
 * bytes and keys rather than rules. docs/vectors/adversarial-certificate.json names each construction and the
 * answer the library must give; this file performs the constructions with a test PKI generated at run time.
 */
import "reflect-metadata";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { OID_ICP_CNPJ, OID_ICP_PERSON, cnpjFromCertificate, cpfFromCertificate, icpCertificateTypes, isElectronicSeal, verifyIcpSignature } from "./icp-brasil.js";
import { checkRevocation } from "./revocation.js";
import { KyaError } from "./types.js";

interface Case { id: string; kind: "crl" | "cms"; construction: string; expect: { revoked?: boolean; cnpj?: string; error?: string; message?: string } }
const FILE = new URL("../../../docs/vectors/adversarial-certificate.json", import.meta.url);
const { cases } = JSON.parse(readFileSync(FILE, "utf8")) as { cases: Case[] };

x509.cryptoProvider.set(globalThis.crypto as Crypto);
pkijs.setEngine("test", new pkijs.CryptoEngine({ name: "test", crypto: globalThis.crypto as Crypto }));
const RSA = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const NOW = new Date("2026-10-12T00:00:00Z");
const CNPJ = "11222333000181";
const CHALLENGE = `KYA Brasil: prove this agent key acts for a company\ncnpj: ${CNPJ}`;

async function ac(name = "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", alg: Algorithm | typeof RSA = RSA) {
  const keys = (await crypto.subtle.generateKey(alg as RsaHashedKeyGenParams, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01", name, notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg as Algorithm, keys,
    extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)]
  });
  return { keys, cert };
}
type Ac = Awaited<ReturnType<typeof ac>>;

function otherNameSan(oid: string, value: string) {
  const other = new OtherName({ typeId: oid, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(value))) });
  return new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
}

/** `policy`: an ICP-Brasil certificate policy OID; `dnSerialOnly`: the identifier only in the DN serialNumber, no otherName (the seal profile after 2028). */
async function leaf(ca: Ac, p: { oid?: string; id?: string; notBefore?: Date; notAfter?: Date; policy?: string; dnSerialOnly?: boolean } = {}) {
  const keys = (await crypto.subtle.generateKey(RSA, true, ["sign", "verify"])) as CryptoKeyPair;
  const id = p.id ?? CNPJ;
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: "0a1b", subject: p.dnSerialOnly ? `CN=ACME LTDA, 2.5.4.5=${id}, O=ICP-Brasil, C=BR` : `CN=ACME LTDA:${id}, O=ICP-Brasil, C=BR`, issuer: ca.cert.subject,
    notBefore: p.notBefore ?? new Date("2026-01-01"), notAfter: p.notAfter ?? new Date("2027-01-01"),
    signingAlgorithm: RSA, publicKey: keys.publicKey, signingKey: ca.keys.privateKey,
    extensions: [
      ...(p.dnSerialOnly ? [] : [otherNameSan(p.oid ?? OID_ICP_CNPJ, id)]),
      ...(p.policy ? [new x509.CertificatePolicyExtension([p.policy])] : []),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true)
    ]
  });
  return { keys, cert };
}

async function crl(ca: Ac, entries: x509.X509CrlEntryParams[], nextUpdate = new Date("2026-10-13T00:00:00Z"), alg: Algorithm | typeof RSA = RSA) {
  return (await x509.X509CrlGenerator.create({ issuer: ca.cert.subject, thisUpdate: new Date("2026-10-11T00:00:00Z"), nextUpdate, signingAlgorithm: alg as Algorithm, signingKey: ca.keys.privateKey, entries })).rawData;
}

async function cms(l: Awaited<ReturnType<typeof leaf>>, ca: Ac, text: string) {
  const leafP = pkijs.Certificate.fromBER(l.cert.rawData);
  const signed = new pkijs.SignedData({
    version: 1, encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: "1.2.840.113549.1.7.1" }),
    signerInfos: [new pkijs.SignerInfo({ version: 1, sid: new pkijs.IssuerAndSerialNumber({ issuer: leafP.issuer, serialNumber: leafP.serialNumber }) })],
    certificates: [leafP, pkijs.Certificate.fromBER(ca.cert.rawData)]
  });
  await signed.sign(l.keys.privateKey, 0, "SHA-256", new TextEncoder().encode(text).buffer as ArrayBuffer);
  return b64(new pkijs.ContentInfo({ contentType: "1.2.840.113549.1.7.2", content: signed.toSchema(true) }).toSchema().toBER(false));
}

function flip(der: ArrayBuffer, index: number) {
  const out = new Uint8Array(der.slice(0));
  out[index] = (out[index] ?? 0) ^ 0x01;
  return out;
}

const LISTED: x509.X509CrlEntryParams = { serialNumber: "0a1b", revocationDate: new Date("2026-10-10T12:00:00Z"), reason: x509.X509CrlReason.keyCompromise };

/** Builds the inputs of one case. Returns a thunk so that the test can assert on its rejection. */
async function build(c: Case): Promise<() => Promise<unknown>> {
  const a = await ac();
  if (c.kind === "crl") {
    const run = (crlDer: ArrayBuffer | Uint8Array, issuer: Ac = a) => () => checkRevocation({ crlDer, serial: "0a1b", issuerCertificate: b64(issuer.cert.rawData), pastNextUpdate: "refuse", now: NOW });
    switch (c.id) {
      case "crl-clean": return run(await crl(a, []));
      case "crl-listed": return run(await crl(a, [LISTED]));
      case "crl-impostor-same-name": return run(await crl(await ac(), []));
      case "crl-foreign-ac": return run(await crl(await ac("CN=Outra AC, O=ICP-Brasil, C=BR"), []));
      case "crl-stale": return run(await crl(a, [], new Date("2026-10-11T12:00:00Z")));
      case "crl-tampered-entry": {
        const der = await crl(a, [LISTED]);
        const bytes = new Uint8Array(der);
        // The listed serial 0x0a1b appears once inside the TBS; flip its low byte.
        const i = bytes.findIndex((b, k) => b === 0x02 && bytes[k + 1] === 0x02 && bytes[k + 2] === 0x0a && bytes[k + 3] === 0x1b);
        expect(i).toBeGreaterThan(0);
        return run(flip(der, i + 3));
      }
      case "crl-tampered-signature": { const der = await crl(a, [LISTED]); return run(flip(der, der.byteLength - 1)); }
      case "crl-truncated": { const der = await crl(a, [LISTED]); return run(der.slice(0, der.byteLength >> 1)); }
      case "crl-garbage": return run(crypto.getRandomValues(new Uint8Array(300)));
      case "crl-unsupported-algorithm": {
        const pss = { name: "RSA-PSS", hash: "SHA-256", saltLength: 32, publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
        const ca2 = await ac("CN=AC PSS, O=ICP-Brasil, C=BR", pss as unknown as Algorithm);
        return run(await crl(ca2, [], undefined, pss as unknown as Algorithm), ca2);
      }
    }
  } else {
    const verify = (cmsBase64: string, p: Partial<Parameters<typeof verifyIcpSignature>[0]> = {}) => () => verifyIcpSignature({ cmsBase64, challenge: CHALLENGE, expectedCnpj: CNPJ, anchors: [b64(a.cert.rawData)], now: NOW, ...p });
    switch (c.id) {
      case "cms-valid": return verify(await cms(await leaf(a), a, CHALLENGE));
      case "cms-other-root": { const b = await ac("CN=AC Desconhecida, O=ICP-Brasil, C=BR"); return verify(await cms(await leaf(b), b, CHALLENGE)); }
      case "cms-expired-leaf": return verify(await cms(await leaf(a, { notBefore: new Date("2025-01-01"), notAfter: new Date("2026-01-01") }), a, CHALLENGE));
      case "cms-not-yet-valid-leaf": return verify(await cms(await leaf(a, { notBefore: new Date("2027-01-01"), notAfter: new Date("2028-01-01") }), a, CHALLENGE));
      case "cms-ecpf-instead-of-ecnpj": return verify(await cms(await leaf(a, { oid: OID_ICP_PERSON, id: "0101198012345678900000000000000000000000000" }), a, CHALLENGE));
      case "cms-cnpj-mismatch": return verify(await cms(await leaf(a), a, CHALLENGE), { expectedCnpj: "99888777000166" });
      case "cms-wrong-text": return verify(await cms(await leaf(a), a, CHALLENGE + " "));
      case "cms-no-anchors": return verify(await cms(await leaf(a), a, CHALLENGE), { anchors: [] });
      case "cms-garbage": return verify(b64(crypto.getRandomValues(new Uint8Array(200)).buffer));
      case "cms-a3-policy": return verify(await cms(await leaf(a, { policy: "2.16.76.1.2.3.1" }), a, CHALLENGE));
      case "cms-seal-software": return verify(await cms(await leaf(a, { policy: "2.16.76.1.2.201.1" }), a, CHALLENGE));
      case "cms-seal-hardware-dn-serial": return verify(await cms(await leaf(a, { policy: "2.16.76.1.2.202.1", dnSerialOnly: true }), a, CHALLENGE));
    }
  }
  throw new Error(`no construction for ${c.id}`);
}

describe("adversarial vectors (H4): certificates and CRLs", () => {
  it("covers every case in the catalogue", () => {
    expect(cases.length).toBeGreaterThanOrEqual(19);
  });
  for (const c of cases) {
    it(`${c.id}: ${c.construction}`, async () => {
      const run = await build(c);
      if (c.expect.error) {
        let caught: unknown = null;
        try { await run(); } catch (e) { caught = e; }
        expect(caught, "expected a refusal").toBeInstanceOf(KyaError);
        expect((caught as KyaError).code).toBe(c.expect.error);
        expect((caught as Error).message).toMatch(new RegExp(c.expect.message!, "i"));
      } else {
        const r = (await run()) as Record<string, unknown>;
        if (c.expect.revoked !== undefined) expect(r.revoked).toBe(c.expect.revoked);
        if (c.expect.cnpj !== undefined) expect(r.cnpj).toBe(c.expect.cnpj);
      }
    });
  }
});

/** Resolução CG ICP-Brasil 211/2024: the identifier moves to the DN serialNumber, and the policy OID names the type. */
describe("certificate profile after Resolução CG ICP-Brasil 211/2024", () => {
  const parsed = (c: { cert: x509.X509Certificate }) => new x509.X509Certificate(c.cert.rawData);

  it("reads the CNPJ from the DN serialNumber when the otherName is absent", async () => {
    const a = await ac();
    expect(cnpjFromCertificate(parsed(await leaf(a, { dnSerialOnly: true })))).toBe(CNPJ);
    expect(cnpjFromCertificate(parsed(await leaf(a)))).toBe(CNPJ); // the otherName still comes first
  });

  it("reads the CPF from the DN serialNumber, and never takes it for a CNPJ", async () => {
    const x = parsed(await leaf(await ac(), { dnSerialOnly: true, id: "12345678909" }));
    expect(cnpjFromCertificate(x)).toBeNull();
    expect(cpfFromCertificate(x)).toBe("12345678909");
  });

  it("tells a seal from a signature certificate by the policy OID only", async () => {
    const a = await ac();
    const seal = parsed(await leaf(a, { policy: "2.16.76.1.2.201.1" }));
    const a3 = parsed(await leaf(a, { policy: "2.16.76.1.2.3.1" }));
    expect(icpCertificateTypes(seal)).toEqual(["201"]);
    expect(isElectronicSeal(seal)).toBe(true);
    expect(isElectronicSeal(parsed(await leaf(a, { policy: "2.16.76.1.2.202.7" })))).toBe(true);
    expect(icpCertificateTypes(a3)).toEqual(["3"]);
    expect(isElectronicSeal(a3)).toBe(false);
    expect(isElectronicSeal(parsed(await leaf(a)))).toBe(false); // no ICP-Brasil policy named: not a seal
  });
});
