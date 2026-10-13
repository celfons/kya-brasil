import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import * as pkijs from "pkijs";
import { OID_ICP_CNPJ, cnpjFromCertificate, verifyIcpSignature } from "./icp-brasil";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");

async function testPki(cnpj = "11222333000181") {
  const caKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)] });
  const leafKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const other = new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(cnpj))) });
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
  const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "02", subject: `CN=ACME LTDA:${cnpj}, O=ICP-Brasil, C=BR`, issuer: ca.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01"), signingAlgorithm: alg, publicKey: leafKeys.publicKey, signingKey: caKeys.privateKey, extensions: [san, new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true)] });
  return { ca, leaf, leafKeys };
}

async function cmsSign(leaf: x509.X509Certificate, ca: x509.X509Certificate, key: CryptoKey, text: string): Promise<string> {
  pkijs.setEngine("test", new pkijs.CryptoEngine({ name: "test", crypto: globalThis.crypto as Crypto }));
  const leafP = pkijs.Certificate.fromBER(leaf.rawData);
  const caP = pkijs.Certificate.fromBER(ca.rawData);
  const signed = new pkijs.SignedData({
    version: 1,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: "1.2.840.113549.1.7.1" }),
    signerInfos: [new pkijs.SignerInfo({ version: 1, sid: new pkijs.IssuerAndSerialNumber({ issuer: leafP.issuer, serialNumber: leafP.serialNumber }) })],
    certificates: [leafP, caP]
  });
  await signed.sign(key, 0, "SHA-256", new TextEncoder().encode(text).buffer as ArrayBuffer);
  const ci = new pkijs.ContentInfo({ contentType: "1.2.840.113549.1.7.2", content: signed.toSchema(true) });
  return b64(ci.toSchema().toBER(false));
}

describe("ICP-Brasil e-CNPJ proof", () => {
  it("reads the CNPJ from the otherName extension", async () => {
    const { leaf } = await testPki();
    expect(cnpjFromCertificate(leaf)).toBe("11222333000181");
  });

  it("verifies a detached CMS signature over the challenge, the CNPJ and the chain", async () => {
    const { ca, leaf, leafKeys } = await testPki();
    const text = "KYA Brasil: prove this agent key acts for a company\nchallenge: c1";
    const cms = await cmsSign(leaf, ca, leafKeys.privateKey, text);
    const proof = await verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: "11.222.333/0001-81", anchors: [b64(ca.rawData)], now: new Date("2026-10-12T00:00:00Z") });
    expect(proof.cnpj).toBe("11222333000181");
    expect(proof.certificate_subject).toContain("ACME LTDA");
    expect(proof.certificate_sha256).toHaveLength(64);
    expect(proof.serial_number).toBe("2");
    expect(proof.crl_urls).toEqual([]);
    expect(proof.issuer_certificate).toBe(b64(ca.rawData));
    await expect(verifyIcpSignature({ cmsBase64: cms, challenge: text + "!", expectedCnpj: "11222333000181", anchors: [b64(ca.rawData)], now: new Date("2026-10-12T00:00:00Z") })).rejects.toThrow(/does not match|failed/);
    await expect(verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: "33000167000101", anchors: [b64(ca.rawData)], now: new Date("2026-10-12T00:00:00Z") })).rejects.toThrow(/belongs to CNPJ/);
    await expect(verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: "11222333000181", anchors: [], now: new Date("2026-10-12T00:00:00Z") })).rejects.toThrow(/trust anchors/);
    await expect(verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: "11222333000181", anchors: [b64(ca.rawData)], now: new Date("2028-01-01T00:00:00Z") })).rejects.toThrow(/valid from/);
  });

  it("rejects a chain that does not end in a configured anchor", async () => {
    const { ca, leaf, leafKeys } = await testPki();
    const { ca: otherCa } = await testPki();
    const text = "challenge";
    const cms = await cmsSign(leaf, ca, leafKeys.privateKey, text);
    await expect(verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: "11222333000181", anchors: [b64(otherCa.rawData)], now: new Date("2026-10-12T00:00:00Z") })).rejects.toThrow(/chain/);
  });
});
