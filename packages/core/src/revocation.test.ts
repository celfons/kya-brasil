/// <reference types="node" /> // test-only: Buffer, node:fs, process
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { type CertificateRevocationPolicy, MAX_CRL_BYTES, certificateRevocationPolicy, checkRevocation, crlUrlsOf, normalizeSerial, revocationEffect, verifyCrl } from "./revocation.js";

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

// Hand-built DER CRL, so it can be as large as a real ICP-Brasil one (@peculiar/x509's generator re-parses what it
// builds and stops at asn1js's 10 000-node default, about 1 240 entries).
const derLen = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 255] : n < 0x1000000 ? [0x83, n >> 16, (n >> 8) & 255, n & 255] : [0x84, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255]);
const tlvOf = (tag: number, parts: Uint8Array[]) => {
  const len = parts.reduce((s, x) => s + x.length, 0);
  const head = Uint8Array.from([tag, ...derLen(len)]);
  const out = new Uint8Array(head.length + len);
  out.set(head);
  let o = head.length;
  for (const x of parts) (out.set(x, o), (o += x.length));
  return out;
};
const tlv = (tag: number, ...parts: Uint8Array[]) => tlvOf(tag, parts);
const utc = (d: Date) => tlv(0x17, new TextEncoder().encode(d.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z"));
const SHA256_RSA = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00]);
const REASON_KEY_COMPROMISE = Uint8Array.from([0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x15, 0x04, 0x03, 0x0a, 0x01, 0x01]);
async function bigCrl(ca: Awaited<ReturnType<typeof ac>>, n: number, revokedAt: Date) {
  const date = utc(revokedAt);
  const entries = Array.from({ length: n }, (_, i) => tlv(0x30, tlv(0x02, Uint8Array.from([0x40, (i >> 16) & 255, (i >> 8) & 255, i & 255])), date, ...(i % 2 ? [tlv(0x30, REASON_KEY_COMPROMISE)] : [])));
  const tbs = tlv(0x30, Uint8Array.from([2, 1, 1]), SHA256_RSA, new Uint8Array(new x509.Name(ca.cert.subject).toArrayBuffer()), utc(new Date("2026-10-11T00:00:00Z")), utc(new Date("2026-10-13T00:00:00Z")), tlvOf(0x30, entries));
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", ca.keys.privateKey, tbs));
  return tlv(0x30, tbs, SHA256_RSA, tlv(0x03, Uint8Array.of(0), sig));
}

describe("large CRLs (AC SERPRO RFB v5 lists ~77 000 entries)", () => {
  it("verifies and looks up a 200 000-entry CRL (refused before core 0.19.1: asn1js node limit)", async () => {
    const a = await ac();
    const der = await bigCrl(a, 200_000, new Date("2026-10-01T00:00:00Z"));
    expect(der.length).toBeGreaterThan(4_000_000);
    const crl = await verifyCrl({ crlDer: der, issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now });
    expect(crl.lookup("40030d3f")).toMatchObject({ revoked: true, revoked_at: "2026-10-01T00:00:00.000Z", reason: "keyCompromise" }); // i = 199 999
    expect(crl.lookup("40000000")).toMatchObject({ revoked: true, reason: null });
    expect(crl.lookup("50000000").revoked).toBe(false);
    // One flipped byte in the entries breaks the signature.
    const tampered = der.slice();
    tampered[1000] = tampered[1000]! ^ 1;
    await expect(verifyCrl({ crlDer: tampered, issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now })).rejects.toThrow(/signature|not valid DER/);
  }, 60_000);

  it("refuses input above MAX_CRL_BYTES before parsing it", async () => {
    const a = await ac();
    const huge = new Uint8Array(MAX_CRL_BYTES + 1);
    await expect(verifyCrl({ crlDer: huge, issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now })).rejects.toThrow(/not valid DER: CRL larger than/);
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

describe("EdDSA CRLs (AC Raiz v6 and AC INMETRO sign with Ed448)", () => {
  for (const [name, oidTail] of [["Ed448", 0x71], ["Ed25519", 0x70]] as const) {
    it(`verifies a ${name}-signed CRL and refuses a tampered one`, async () => {
      const keys = (await crypto.subtle.generateKey({ name }, true, ["sign", "verify"])) as CryptoKeyPair;
      const algId = Uint8Array.from([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, oidTail]); // RFC 8410: no parameters
      // Self-signed AC certificate built by hand: @peculiar/x509's generator does not know Ed448.
      const dn = new Uint8Array(new x509.Name("CN=AC Raiz Teste v6, O=ICP-Brasil, C=BR").toArrayBuffer());
      const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
      const tbsCert = tlv(0x30, tlv(0xa0, Uint8Array.from([2, 1, 2])), Uint8Array.from([2, 1, 2]), algId, dn, tlv(0x30, utc(new Date("2026-01-01T00:00:00Z")), utc(new Date("2030-01-01T00:00:00Z"))), dn, spki);
      const certSig = new Uint8Array(await crypto.subtle.sign({ name }, keys.privateKey, tbsCert));
      const cert = new x509.X509Certificate(tlv(0x30, tbsCert, algId, tlv(0x03, Uint8Array.of(0), certSig)));
      const entry = tlv(0x30, tlv(0x02, Uint8Array.of(0x2a)), utc(new Date("2026-10-01T00:00:00Z")), tlv(0x30, REASON_KEY_COMPROMISE));
      const tbs = tlv(0x30, Uint8Array.from([2, 1, 1]), algId, new Uint8Array(new x509.Name(cert.subject).toArrayBuffer()), utc(new Date("2026-10-11T00:00:00Z")), utc(new Date("2026-10-13T00:00:00Z")), tlv(0x30, entry));
      const sig = new Uint8Array(await crypto.subtle.sign({ name }, keys.privateKey, tbs));
      const der = tlv(0x30, tbs, algId, tlv(0x03, Uint8Array.of(0), sig));
      const crl = await verifyCrl({ crlDer: der, issuerCertificate: b64(cert.rawData), pastNextUpdate: "refuse", now });
      expect(crl.lookup("2a")).toMatchObject({ revoked: true, reason: "keyCompromise" });
      const tampered = der.slice();
      tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
      await expect(verifyCrl({ crlDer: tampered, issuerCertificate: b64(cert.rawData), pastNextUpdate: "refuse", now })).rejects.toThrow(/signature/);
    });
  }

  it("refuses an unidentified algorithm (AC Raiz v7: 1.3.6.1.4.1.44588.2.1) as unavailable, not as valid", async () => {
    const a = await ac();
    const algId = tlv(0x30, tlv(0x06, Uint8Array.from([0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01])));
    const tbs = tlv(0x30, Uint8Array.from([2, 1, 1]), algId, new Uint8Array(new x509.Name(a.cert.subject).toArrayBuffer()), utc(new Date("2026-10-11T00:00:00Z")), utc(new Date("2026-10-13T00:00:00Z")));
    const der = tlv(0x30, tbs, algId, tlv(0x03, Uint8Array.of(0), Uint8Array.of(1, 2, 3)));
    await expect(verifyCrl({ crlDer: der, issuerCertificate: b64(a.cert.rawData), pastNextUpdate: "refuse", now })).rejects.toThrow(/1\.3\.6\.1\.4\.1\.44588\.2\.1 is not supported/);
  });
});
