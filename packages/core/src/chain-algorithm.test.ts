/// <reference types="node" /> // test-only: Buffer
// A chain the library cannot verify is refused with the algorithm named. The newer ICP-Brasil roots sign with
// Edwards curves (Ed448, Ed521); the test uses Ed25519, the Edwards curve Web Crypto can sign with here.
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { ecnpjSigner } from "./ecnpj-sign.js";
import { OID_ICP_CNPJ, verifyIcpSignature } from "./icp-brasil.js";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const RSA = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const ECDSA = { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384" };
const ED25519 = { name: "Ed25519" };
const CNPJ = "11222333000181";
const NOW = new Date("2026-11-04T12:00:00Z");
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");

/** An e-CNPJ with an RSA key under a root that signs with `caAlg`, and a CMS it signs over "hello". */
async function signedUnder(caAlg: object) {
  const caKeys = (await crypto.subtle.generateKey(caAlg as RsaHashedKeyGenParams, true, ["sign", "verify"])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste, O=ICP-Brasil TESTE, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2031-01-01"), signingAlgorithm: caAlg as Algorithm, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  const keys = (await crypto.subtle.generateKey(RSA, true, ["sign", "verify"])) as CryptoKeyPair;
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(CNPJ))) }) })])));
  const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "02", subject: `CN=ACME LTDA:${CNPJ}, O=ICP-Brasil TESTE, C=BR`, issuer: ca.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: caAlg as Algorithm, publicKey: keys.publicKey, signingKey: caKeys.privateKey, extensions: [san] });
  const signer = ecnpjSigner({ certificates: [new Uint8Array(leaf.rawData), new Uint8Array(ca.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, d.slice().buffer as ArrayBuffer)) });
  return { cms: await signer.sign("hello"), anchor: b64(ca.rawData) };
}
const verify = (cmsBase64: string, anchors: string[]) => verifyIcpSignature({ cmsBase64, challenge: "hello", expectedCnpj: CNPJ, anchors, now: NOW });

describe("the algorithm of the certificate chain", () => {
  it("accepts a chain signed with RSA or with ECDSA on a NIST curve", async () => {
    for (const alg of [RSA, ECDSA]) {
      const { cms, anchor } = await signedUnder(alg);
      expect((await verify(cms, [anchor])).cnpj).toBe(CNPJ);
    }
  });

  it("refuses a chain signed with an Edwards curve and names the algorithm", async () => {
    const { cms, anchor } = await signedUnder(ED25519);
    await expect(verify(cms, [anchor])).rejects.toMatchObject({ code: "CERTIFICATE_INVALID", message: "certificate chain signed with Ed25519 (1.3.101.112), which is not supported (RSA and ECDSA on NIST curves are)" });
  });

  it("still says a supported chain under another root is not trusted", async () => {
    const mine = await signedUnder(RSA);
    const other = await signedUnder(RSA);
    await expect(verify(mine.cms, [other.anchor])).rejects.toMatchObject({ code: "CERTIFICATE_INVALID", message: expect.stringMatching(/^certificate chain not trusted: /) });
    // An Edwards root among the anchors does not change the answer for a chain that does not use it.
    const edwards = await signedUnder(ED25519);
    expect((await verify(mine.cms, [edwards.anchor, mine.anchor])).cnpj).toBe(CNPJ);
    await expect(verify(mine.cms, [edwards.anchor])).rejects.toMatchObject({ message: expect.stringMatching(/^certificate chain not trusted: /) });
  });
});
