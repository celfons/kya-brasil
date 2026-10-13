import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { checkRevocation, crlUrlsOf, normalizeSerial, revocationEffect } from "./revocation";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const now = new Date("2026-10-12T00:00:00Z");

async function ac(name = "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR") {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name, notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  return { keys, cert };
}

async function leafOf(ca: Awaited<ReturnType<typeof ac>>, serialNumber = "0a1b") {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  return x509.X509CertificateGenerator.create({
    serialNumber, subject: "CN=ACME LTDA:11222333000181, O=ICP-Brasil, C=BR", issuer: ca.cert.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01"),
    signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: ca.keys.privateKey,
    extensions: [new x509.CRLDistributionPointsExtension(["http://lcr.ac-teste.br/ac.crl", "http://repositorio.icpbrasil.gov.br/lcr/ac.crl", "ldap://ignored"])]
  });
}

async function crlOf(ca: Awaited<ReturnType<typeof ac>>, entries: x509.X509CrlEntryParams[], nextUpdate = new Date("2026-10-13T00:00:00Z")) {
  return x509.X509CrlGenerator.create({ issuer: ca.cert.subject, thisUpdate: new Date("2026-10-11T00:00:00Z"), nextUpdate, signingAlgorithm: alg, signingKey: ca.keys.privateKey, entries });
}

describe("e-CNPJ revocation (LCR)", () => {
  it("reads the HTTP distribution points of the certificate", async () => {
    const leaf = await leafOf(await ac());
    expect(crlUrlsOf(leaf)).toEqual(["http://lcr.ac-teste.br/ac.crl", "http://repositorio.icpbrasil.gov.br/lcr/ac.crl"]);
  });

  it("finds a revoked serial and passes a clean one", async () => {
    const a = await ac();
    const crl = await crlOf(a, [{ serialNumber: "0a1b", revocationDate: new Date("2026-10-10T12:00:00Z"), reason: x509.X509CrlReason.keyCompromise }]);
    const revoked = await checkRevocation({ crlDer: crl.rawData, serial: "A1B", issuerCertificate: b64(a.cert.rawData), now });
    expect(revoked).toMatchObject({ revoked: true, revoked_at: "2026-10-10T12:00:00.000Z", reason: "keyCompromise" });
    const clean = await checkRevocation({ crlDer: crl.rawData, serial: "0c0d", issuerCertificate: b64(a.cert.rawData), now });
    expect(clean).toMatchObject({ revoked: false, revoked_at: null, crl_next_update: "2026-10-13T00:00:00.000Z" });
  });

  it("refuses a CRL that is stale, from another AC or signed by another key", async () => {
    const a = await ac();
    const stale = await crlOf(a, [], new Date("2026-10-11T12:00:00Z"));
    await expect(checkRevocation({ crlDer: stale.rawData, serial: "01", issuerCertificate: b64(a.cert.rawData), now })).rejects.toThrow(/stale/);
    const other = await ac("CN=Outra AC, O=ICP-Brasil, C=BR");
    const foreign = await crlOf(other, []);
    await expect(checkRevocation({ crlDer: foreign.rawData, serial: "01", issuerCertificate: b64(a.cert.rawData), now })).rejects.toThrow(/not by the certificate's AC/);
    const impostor = await ac();
    const forged = await crlOf(impostor, []);
    await expect(checkRevocation({ crlDer: forged.rawData, serial: "01", issuerCertificate: b64(a.cert.rawData), now })).rejects.toThrow(/signature/);
    await expect(checkRevocation({ crlDer: new Uint8Array([1, 2, 3]), serial: "01", issuerCertificate: b64(a.cert.rawData), now })).rejects.toThrow(/not valid DER/);
  });

  it("normalizes serials", () => {
    expect(normalizeSerial("00AB")).toBe("ab");
    expect(normalizeSerial("0")).toBe("0");
  });
});

describe("revocation effect on an issued credential", () => {
  const at = "2026-10-01T00:00:00Z";
  it("revokes on compromise or unspecified, suspends on hold, ignores a later benign replacement", () => {
    expect(revocationEffect({ revoked: false, revoked_at: null, reason: null }, at)).toBe("none");
    expect(revocationEffect({ revoked: true, revoked_at: "2026-10-05T00:00:00Z", reason: "keyCompromise" }, at)).toBe("revoke");
    expect(revocationEffect({ revoked: true, revoked_at: "2026-10-05T00:00:00Z", reason: null }, at)).toBe("revoke");
    expect(revocationEffect({ revoked: true, revoked_at: "2026-10-05T00:00:00Z", reason: "certificateHold" }, at)).toBe("suspend");
    expect(revocationEffect({ revoked: true, revoked_at: "2026-10-05T00:00:00Z", reason: "superseded" }, at)).toBe("none");
    expect(revocationEffect({ revoked: true, revoked_at: "2026-09-05T00:00:00Z", reason: "superseded" }, at)).toBe("revoke");
  });
});
