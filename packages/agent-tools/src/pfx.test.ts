/// <reference types="node" />
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import forge from "node-forge";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { OID_ICP_CNPJ, verifyIcpSignature } from "@kya-brasil/core";
import { openPfx, signWithECnpjPfx } from "./pfx";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const pem = (der: ArrayBuffer, label: string) => `-----BEGIN ${label}-----\n${b64(der).replace(/(.{64})/g, "$1\n")}\n-----END ${label}-----`;

/** A test ICP-Brasil-like chain and the company's A1 file, as a .pfx with the given PKCS#12 encryption. */
async function a1File(algorithm: "3des" | "aes256", cnpj = "11222333000181") {
  const caKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)] });
  const leafKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const other = new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(cnpj))) });
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
  const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "02", subject: `CN=ACME LTDA:${cnpj}, O=ICP-Brasil, C=BR`, issuer: ca.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01"), signingAlgorithm: alg, publicKey: leafKeys.publicKey, signingKey: caKeys.privateKey, extensions: [san, new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true)] });
  const key = forge.pki.privateKeyFromPem(pem(await crypto.subtle.exportKey("pkcs8", leafKeys.privateKey), "PRIVATE KEY"));
  const certs = [leaf, ca].map((c) => forge.pki.certificateFromPem(pem(c.rawData, "CERTIFICATE")));
  const p12 = forge.pkcs12.toPkcs12Asn1(key, certs, "senha-teste", { algorithm: algorithm });
  return { pfx: new Uint8Array(Buffer.from(forge.asn1.toDer(p12).getBytes(), "binary")), ca };
}

describe("e-CNPJ signing from a .pfx (A1)", () => {
  for (const algorithm of ["3des", "aes256"] as const) {
    it(`signs a detached CMS the issuer accepts (${algorithm} PKCS#12)`, async () => {
      const { pfx, ca } = await a1File(algorithm);
      const text = "KYA Brasil: prove this agent key acts for a company\nchallenge: c1\ncnpj: 11222333000181";
      const signer = openPfx(pfx, "senha-teste");
      expect(signer.cnpj).toBe("11222333000181");
      expect(signer.subject).toContain("ACME LTDA");
      const cms = signer.sign(text);
      const proof = await verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: "11222333000181", anchors: [b64(ca.rawData)], now: new Date("2026-10-14T00:00:00Z") });
      expect(proof.cnpj).toBe("11222333000181");
      await expect(verifyIcpSignature({ cmsBase64: cms, challenge: text + "\n", expectedCnpj: "11222333000181", anchors: [b64(ca.rawData)], now: new Date("2026-10-14T00:00:00Z") })).rejects.toThrow();
    });
  }

  it("says so on a wrong password", async () => {
    const { pfx } = await a1File("3des");
    expect(() => signWithECnpjPfx(pfx, "errada", "x")).toThrow(/wrong password/);
  });
});
