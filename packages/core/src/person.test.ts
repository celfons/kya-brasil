/// <reference types="node" />
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import * as pkijs from "pkijs";
import { OID_ICP_CNPJ, OID_ICP_PERSON, verifyIcpPersonSignature, verifyIcpSignature } from "./icp-brasil.js";
import { isValidCpf, newPersonChallenge, normalizeCpf, personHash, personKeys, subjectRef } from "./person.js";
import { buildPersonCredential } from "./credential.js";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const CPF = "52998224725";
const KEY = Buffer.alloc(32, 7).toString("base64");

async function pki(kind: "person" | "company") {
  const caKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const other = kind === "person"
    ? new OtherName({ typeId: OID_ICP_PERSON, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(`01011990${CPF}00000000000000000000000000000`))) })
    : new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode("11222333000181"))) });
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
  const subject = kind === "person" ? `CN=MARIA DA SILVA:${CPF}, O=ICP-Brasil, C=BR` : "CN=ACME LTDA:11222333000181, O=ICP-Brasil, C=BR";
  const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "02", subject, issuer: ca.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: caKeys.privateKey, extensions: [san] });
  return { ca, leaf, keys };
}

async function cms(leaf: x509.X509Certificate, ca: x509.X509Certificate, key: CryptoKey, text: string) {
  pkijs.setEngine("t", new pkijs.CryptoEngine({ name: "t", crypto: globalThis.crypto as Crypto }));
  const lp = pkijs.Certificate.fromBER(leaf.rawData);
  const signed = new pkijs.SignedData({ version: 1, encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: "1.2.840.113549.1.7.1" }), signerInfos: [new pkijs.SignerInfo({ version: 1, sid: new pkijs.IssuerAndSerialNumber({ issuer: lp.issuer, serialNumber: lp.serialNumber }) })], certificates: [lp, pkijs.Certificate.fromBER(ca.rawData)] });
  await signed.sign(key, 0, "SHA-256", new TextEncoder().encode(text).buffer as ArrayBuffer);
  return b64(new pkijs.ContentInfo({ contentType: "1.2.840.113549.1.7.2", content: signed.toSchema(true) }).toSchema().toBER(false));
}

const now = new Date("2026-10-14T00:00:00Z");

describe("natural persons (D-29)", () => {
  it("validates CPFs", () => {
    expect(isValidCpf(CPF)).toBe(true);
    expect(isValidCpf("529.982.247-25")).toBe(true);
    expect(isValidCpf("52998224724")).toBe(false);
    expect(isValidCpf("11111111111")).toBe(false);
    expect(() => normalizeCpf("123")).toThrow(/valid Brazilian CPF/);
  });

  it("verifies an e-CPF signature and reads the CPF, without any subject in the proof", async () => {
    const { ca, leaf, keys } = await pki("person");
    const ch = newPersonChallenge({ issuer: "https://kya.test", agent: { kind: "evm", id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" }, now });
    expect(ch.text).toContain("consent: I authorize");
    expect(ch.text).not.toMatch(/cnpj:/);
    const sig = await cms(leaf, ca, keys.privateKey, ch.text);
    const proof = await verifyIcpPersonSignature({ cmsBase64: sig, challenge: ch.text, anchors: [b64(ca.rawData)], now });
    expect(proof.cpf).toBe(CPF);
    expect(JSON.stringify(proof)).not.toContain("MARIA");
    // The company path refuses it with a clear message, and the person path refuses an e-CNPJ.
    await expect(verifyIcpSignature({ cmsBase64: sig, challenge: ch.text, expectedCnpj: "11222333000181", anchors: [b64(ca.rawData)], now })).rejects.toThrow(/e-CPF/);
    const company = await pki("company");
    const csig = await cms(company.leaf, company.ca, company.keys.privateKey, ch.text);
    await expect(verifyIcpPersonSignature({ cmsBase64: csig, challenge: ch.text, anchors: [b64(company.ca.rawData)], now })).rejects.toThrow(/e-CNPJ/);
  });

  it("keyed hashes: stable, key-bound, pairwise subject references", async () => {
    const h = await personHash(KEY, CPF);
    expect(await personHash(KEY, "529.982.247-25")).toBe(h);
    expect(await personHash(Buffer.alloc(32, 8).toString("base64"), CPF)).not.toBe(h);
    const a = await subjectRef(KEY, h, "0xAAAA");
    expect(await subjectRef(KEY, h, "0xaaaa")).toBe(a);
    expect(await subjectRef(KEY, h, "0xBBBB")).not.toBe(a);
    await expect(personHash(Buffer.alloc(8).toString("base64"), CPF)).rejects.toThrow(/32 bytes/);
    const k = personKeys(JSON.stringify({ "1": KEY, "2": Buffer.alloc(32, 9).toString("base64") }));
    expect(k?.current.version).toBe(2);
    expect(k?.all.size).toBe(2);
    expect(personKeys(undefined)).toBeNull();
  });

  it("the person credential carries nothing personal", () => {
    const c = buildPersonCredential({ credential_id: "c1", agent: { kind: "evm", id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" }, certificate: { sha256: "ab".repeat(32), issuer: "CN=AC Teste", signed_at: now.toISOString() }, mandate: { actions: ["buy"] }, issuer: "https://kya.test", now });
    expect(c.principal).toEqual({ kind: "person", verified_by: "icp-brasil-e-cpf" });
    expect(c.authorized_by.method).toBe("icp-brasil-e-cpf");
    expect(c.authorized_by.certificate_subject).toBeUndefined();
    expect(JSON.stringify(c)).not.toMatch(/\d{11}/);
  });
});
