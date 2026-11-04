/// <reference types="node" /> // test-only: Buffer, node:fs, process
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { type CertificateRevocationPolicy, certificateRevocationPolicy, checkRevocation, crlUrlsOf, normalizeSerial, revocationEffect, verifyCrl } from "./revocation.js";

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
    const revoked = await checkRevocation({ crlDer: crl.rawData, serial: "A1B", issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now });
    expect(revoked).toMatchObject({ revoked: true, revoked_at: "2026-10-10T12:00:00.000Z", reason: "keyCompromise" });
    const clean = await checkRevocation({ crlDer: crl.rawData, serial: "0c0d", issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now });
    expect(clean).toMatchObject({ revoked: false, revoked_at: null, crl_next_update: "2026-10-13T00:00:00.000Z" });
  });

  it("refuses a CRL that is stale, from another AC or signed by another key", async () => {
    const a = await ac();
    const stale = await crlOf(a, [], new Date("2026-10-11T12:00:00Z"));
    await expect(checkRevocation({ crlDer: stale.rawData, serial: "01", issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now })).rejects.toThrow(/stale/);
    const accepted = await checkRevocation({ crlDer: stale.rawData, serial: "01", issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "accept", now });
    expect(accepted).toMatchObject({ revoked: false, crl_next_update: expect.any(String) });
    await expect(checkRevocation({ crlDer: stale.rawData, serial: "01", issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "maybe" as "accept", now })).rejects.toThrow(/pastNextUpdate is required/);
    const other = await ac("CN=Outra AC, O=ICP-Brasil, C=BR");
    const foreign = await crlOf(other, []);
    await expect(checkRevocation({ crlDer: foreign.rawData, serial: "01", issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now })).rejects.toThrow(/not by the certificate's AC/);
    const impostor = await ac();
    const forged = await crlOf(impostor, []);
    await expect(checkRevocation({ crlDer: forged.rawData, serial: "01", issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now })).rejects.toThrow(/signature/);
    await expect(checkRevocation({ crlDer: new Uint8Array([1, 2, 3]), serial: "01", issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now })).rejects.toThrow(/not valid DER/);
  });

  it("normalizes serials", () => {
    expect(normalizeSerial("00AB")).toBe("ab");
    expect(normalizeSerial("0")).toBe("0");
  });
});

describe("revocation effect on an issued credential (D-16, D-36)", () => {
  const at = "2026-10-01T00:00:00Z";
  // The reference issuer's policy (SPEC section 11); the core has none of its own.
  const reference: CertificateRevocationPolicy = { by_reason: { certificateHold: "suspend", superseded: "keep", cessationOfOperation: "keep" }, other: "revoke" };
  const entry = (reason: string | null, revoked_at = "2026-10-05T00:00:00Z", invalidity_date: string | null = null) => ({ revoked: true, revoked_at, reason, invalidity_date });

  it("applies the caller's policy: revoke on compromise or no reason, suspend on hold, keep a later benign replacement", () => {
    expect(revocationEffect({ revoked: false, revoked_at: null, reason: null }, at, reference)).toBe("none");
    expect(revocationEffect(entry("keyCompromise"), at, reference)).toBe("revoke");
    expect(revocationEffect(entry(null), at, reference)).toBe("revoke");
    expect(revocationEffect(entry("certificateHold"), at, reference)).toBe("suspend");
    expect(revocationEffect(entry("superseded"), at, reference)).toBe("none");
    expect(revocationEffect(entry("superseded", "2026-09-05T00:00:00Z"), at, reference)).toBe("revoke");
  });

  it("another verifier may decide otherwise, e.g. suspend everything until it looks", () => {
    const cautious: CertificateRevocationPolicy = { by_reason: {}, other: "suspend" };
    expect(revocationEffect(entry("superseded"), at, cautious)).toBe("suspend");
    expect(revocationEffect(entry("keyCompromise"), at, { by_reason: { affiliationChanged: "keep" }, other: "revoke" })).toBe("revoke");
    expect(revocationEffect(entry("affiliationChanged"), at, { by_reason: { affiliationChanged: "keep" }, other: "revoke" })).toBe("none");
  });

  it("never keeps what was signed after the suspected compromise, or without a date to compare", () => {
    const lenient: CertificateRevocationPolicy = { by_reason: { keyCompromise: "keep" }, other: "revoke" };
    expect(revocationEffect(entry("keyCompromise", "2026-10-05T00:00:00Z", "2026-10-03T00:00:00Z"), at, lenient)).toBe("none");
    expect(revocationEffect(entry("keyCompromise", "2026-10-05T00:00:00Z", "2026-09-20T00:00:00Z"), at, lenient)).toBe("revoke");
    expect(revocationEffect(entry("superseded"), null, reference)).toBe("revoke");
    expect(revocationEffect(entry("superseded"), "not a date", reference)).toBe("revoke");
  });

  it("requires a complete policy, with no default", () => {
    expect(() => revocationEffect(entry("keyCompromise"), at, undefined as unknown as CertificateRevocationPolicy)).toThrow(/policy is required/);
    expect(() => revocationEffect(entry("keyCompromise"), at, { by_reason: {}, other: "keep" as "revoke" })).toThrow(/never ignored/);
    expect(() => revocationEffect(entry("keyCompromise"), at, { by_reason: { stolen: "revoke" } as never, other: "revoke" })).toThrow(/RFC 5280/);
    expect(() => revocationEffect(entry("keyCompromise"), at, { by_reason: { superseded: "ignore" as "keep" }, other: "revoke" })).toThrow(/must be/);
    expect(() => certificateRevocationPolicy({ other: "revoke" } as CertificateRevocationPolicy)).toThrow(/by_reason is required/);
  });

  it("reads the invalidity date the AC records", async () => {
    const a = await ac();
    const crl = await crlOf(a, [{ serialNumber: "0a1b", revocationDate: new Date("2026-10-10T12:00:00Z"), reason: x509.X509CrlReason.keyCompromise, invalidity: new Date("2026-10-09T00:00:00Z") }, { serialNumber: "0c0d", revocationDate: new Date("2026-10-10T12:00:00Z") }]);
    const verified = await verifyCrl({ crlDer: crl.rawData, issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now });
    expect(verified.lookup("0a1b")).toMatchObject({ reason: "keyCompromise", invalidity_date: "2026-10-09T00:00:00.000Z" });
    expect(verified.lookup("0c0d")).toMatchObject({ reason: null, invalidity_date: null });
  });
});
