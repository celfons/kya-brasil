/// <reference types="node" /> // test-only: Buffer
// The DER reader of CRLs, on lists built byte by byte. Mutation testing (research/mutation) showed that most of
// its refusals and several of its readings had no test: a real CRL never has a truncated length or a field out of
// place, so only hand-built ones reach them. The signature is not verified here (revocation.test.ts does that).
import { describe, expect, it } from "vitest";
import { DerError, ecdsaDerToRaw, parseCrlDer } from "./crl-der.js";

const cat = (...parts: (Uint8Array | number[])[]) => Uint8Array.from(parts.flatMap((p) => [...p]));
const len = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 255]);
const tlv = (tag: number, ...parts: (Uint8Array | number[])[]) => {
  const body = cat(...parts);
  return cat([tag], len(body.length), body);
};
const ascii = (s: string) => [...Buffer.from(s, "ascii")];
const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const NULL = [0x05, 0x00];
const OID_SHA256_RSA = tlv(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
const ALG = tlv(0x30, OID_SHA256_RSA, NULL);
const ISSUER = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, [0x55, 0x04, 0x03]), tlv(0x13, ascii("AC Teste")))));
const utc = (s: string) => tlv(0x17, ascii(s));
const gen = (s: string) => tlv(0x18, ascii(s));
const THIS = utc("261107210000Z");
const NEXT = utc("261108030000Z");
const SIGNATURE = tlv(0x03, [0x00, 0xde, 0xad, 0xbe, 0xef]);
const REASON = (code: number) => tlv(0x30, tlv(0x06, [0x55, 0x1d, 0x15]), tlv(0x04, tlv(0x0a, [code])));
const INVALIDITY = (when: string) => tlv(0x30, tlv(0x06, [0x55, 0x1d, 0x18]), tlv(0x04, gen(when)));
const entry = (serial: number[], date: Uint8Array | null, ...exts: Uint8Array[]) => tlv(0x30, tlv(0x02, serial), ...(date ? [date] : []), ...(exts.length ? [tlv(0x30, ...exts)] : []));
const crlOf = (tbsFields: Uint8Array[], outerAlg: Uint8Array = ALG, signature: Uint8Array = SIGNATURE) => tlv(0x30, tlv(0x30, ...tbsFields), outerAlg, signature);
const refuses = (der: Uint8Array | number[], message: string) => {
  let thrown: unknown;
  try {
    parseCrlDer(Uint8Array.from(der));
  } catch (e) {
    thrown = e;
  }
  expect(thrown, message).toBeInstanceOf(DerError);
  expect((thrown as Error).message).toBe(message);
};

describe("parseCrlDer: what it reads", () => {
  it("reads the smallest list: no version, no nextUpdate, no entries", () => {
    const der = crlOf([ALG, ISSUER, THIS]);
    const crl = parseCrlDer(der);
    expect(crl.thisUpdate.toISOString()).toBe("2026-11-07T21:00:00.000Z");
    expect(crl.nextUpdate).toBeNull();
    expect(crl.entryCount).toBe(0);
    expect(crl.entry("1")).toBeNull();
    expect(crl.signatureAlgorithm).toBe("1.2.840.113549.1.1.11");
    expect(crl.signatureAlgorithmParams).toBeNull();
    expect(hex(crl.signature)).toBe("deadbeef");
    expect(hex(crl.issuerDer)).toBe(hex(ISSUER));
    expect(hex(crl.tbs)).toBe(hex(tlv(0x30, ALG, ISSUER, THIS)));
  });

  it("reads every field of a full list, and each entry on lookup", () => {
    const entries = tlv(
      0x30,
      entry([0x0a, 0x1b], utc("261106120000Z")),
      entry([0x00, 0xff], utc("261106130000Z"), REASON(1), INVALIDITY("20261105100000Z")),
      entry([0x00], utc("261106140000Z"), REASON(9)),
      // A negative serial (RFC 5280 forbids it; two Serpro lists have some) is indexed by its bytes.
      entry([0xcf, 0x43], utc("261106150000Z"))
    );
    const crl = parseCrlDer(crlOf([tlv(0x02, [0x01]), ALG, ISSUER, THIS, NEXT, entries, tlv(0xa0, tlv(0x30))]));
    expect(crl.nextUpdate?.toISOString()).toBe("2026-11-08T03:00:00.000Z");
    expect(crl.entryCount).toBe(4);
    expect(crl.entry("a1b")).toEqual({ revocationDate: new Date("2026-11-06T12:00:00Z") });
    expect(crl.entry("ff")).toEqual({ revocationDate: new Date("2026-11-06T13:00:00Z"), reason: 1, invalidity: new Date("2026-11-05T10:00:00Z") });
    expect(crl.entry("0")).toEqual({ revocationDate: new Date("2026-11-06T14:00:00Z"), reason: 9 });
    expect(crl.entry("cf43")).toEqual({ revocationDate: new Date("2026-11-06T15:00:00Z") });
    for (const absent of ["0a1b", "00ff", "00", "1", "a1", ""]) expect(crl.entry(absent), absent).toBeNull();
  });

  it("reads a time in either form, with the century of a two-digit year and the fraction of a four-digit one", () => {
    const at = (time: Uint8Array) => parseCrlDer(crlOf([ALG, ISSUER, time])).thisUpdate.toISOString();
    expect(at(utc("491231235959Z"))).toBe("2049-12-31T23:59:59.000Z");
    expect(at(utc("500101000000Z"))).toBe("1950-01-01T00:00:00.000Z");
    expect(at(gen("20500101000000Z"))).toBe("2050-01-01T00:00:00.000Z");
    expect(at(gen("20261107210000.5Z"))).toBe("2026-11-07T21:00:00.500Z");
    for (const bad of [utc("2611072100Z"), utc("261107210000"), utc("20261107210000Z"), utc("x261107210000Z"), utc("261107210000Zx"), utc("261307210000Z"), gen("261107210000Z"), gen("20261107210000"), gen("x20261107210000Z"), gen("20261107210000Zx"), gen("20261107210000.Z")]) {
      expect(() => parseCrlDer(crlOf([ALG, ISSUER, bad])), Buffer.from(bad).toString("latin1")).toThrow(/^not a DER time: /);
    }
    // nextUpdate is read with the same rule.
    expect(() => parseCrlDer(crlOf([ALG, ISSUER, THIS, utc("261308030000Z")]))).toThrow('not a DER time: "261308030000Z"');
  });

  it("decodes the algorithm OID arc by arc, and keeps parameters that are not NULL", () => {
    const oidOf = (bytes: number[]) => {
      const alg = tlv(0x30, tlv(0x06, bytes));
      return parseCrlDer(crlOf([alg, ISSUER, THIS], alg));
    };
    expect(oidOf([0x09]).signatureAlgorithm).toBe("0.9");
    expect(oidOf([0x27]).signatureAlgorithm).toBe("0.39");
    expect(oidOf([0x28]).signatureAlgorithm).toBe("1.0");
    expect(oidOf([0x4f]).signatureAlgorithm).toBe("1.39");
    expect(oidOf([0x50]).signatureAlgorithm).toBe("2.0");
    expect(oidOf([0x88, 0x37, 0x03]).signatureAlgorithm).toBe("2.999.3");
    expect(oidOf([0x2b, 0x65, 0x71]).signatureAlgorithm).toBe("1.3.101.113"); // Ed448
    expect(oidOf([0x2b, 0x65, 0x71]).signatureAlgorithmParams).toBeNull();
    const explicit = tlv(0x30, OID_SHA256_RSA, tlv(0x04, [0x01, 0x02]));
    expect(hex(parseCrlDer(crlOf([explicit, ISSUER, THIS], explicit)).signatureAlgorithmParams as Uint8Array)).toBe("04020102");
    const noOid = tlv(0x30, NULL);
    expect(() => parseCrlDer(crlOf([noOid, ISSUER, THIS], noOid))).toThrow(/^expected OBJECT IDENTIFIER at \d+$/);
  });

  it("ignores entry extensions it does not know, and a value of the wrong type in the ones it knows", () => {
    const unknown = tlv(0x30, tlv(0x06, [0x55, 0x1d, 0x1d]), tlv(0x04, tlv(0x30)));
    const critical = tlv(0x30, tlv(0x06, [0x55, 0x1d, 0x15]), [0x01, 0x01, 0xff], tlv(0x04, tlv(0x0a, [4])));
    const reasonAsInteger = tlv(0x30, tlv(0x06, [0x55, 0x1d, 0x15]), tlv(0x04, tlv(0x02, [1])));
    const invalidityAsUtc = tlv(0x30, tlv(0x06, [0x55, 0x1d, 0x18]), tlv(0x04, utc("261105100000Z")));
    const notOctets = tlv(0x30, tlv(0x06, [0x55, 0x1d, 0x15]), tlv(0x0a, [1]));
    const date = utc("261106120000Z");
    const crl = parseCrlDer(crlOf([ALG, ISSUER, THIS, tlv(0x30, entry([1], date, unknown), entry([2], date, critical), entry([3], date, reasonAsInteger, invalidityAsUtc, notOctets), entry([4], date, REASON(0x01), unknown))]));
    const plain = { revocationDate: new Date("2026-11-06T12:00:00Z") };
    expect(crl.entry("1")).toEqual(plain);
    expect(crl.entry("2")).toEqual({ ...plain, reason: 4 });
    expect(crl.entry("3")).toEqual(plain);
    expect(crl.entry("4")).toEqual({ ...plain, reason: 1 });
  });
});

describe("parseCrlDer: what it refuses, and why", () => {
  const good = crlOf([ALG, ISSUER, THIS]);

  it("refuses bytes that are not one DER element spanning the input", () => {
    refuses([], "truncated TLV at 0");
    refuses([0x30], "truncated TLV at 0");
    refuses([0x1f, 0x00], "multi-byte tag at 0");
    refuses([0x3f, 0x00], "multi-byte tag at 0");
    refuses([0x30, 0x80, 0x00, 0x00], "indefinite length at 0 (not DER)");
    refuses([0x30, 0x85, 0, 0, 0, 0, 0], "length too long at 0");
    refuses([0x30, 0x82, 0x01], "truncated length at 0");
    refuses([0x30, 0x02, 0x05], "value overruns its container at 0");
    refuses(cat(good, [0x00]), "not a DER SEQUENCE spanning the input");
    refuses(cat([0x31], good.subarray(1)), "not a DER SEQUENCE spanning the input");
    // A length written in four bytes is long, not wrong.
    const four = cat([0x30, 0x84, 0, 0, 0, good.length - 2], good.subarray(2));
    expect(parseCrlDer(four).entryCount).toBe(0);
  });

  it("refuses an envelope that is not TBSCertList, algorithm and signature", () => {
    const tbs = tlv(0x30, ALG, ISSUER, THIS);
    refuses(tlv(0x30, tbs, ALG), "not a CertificateList");
    refuses(tlv(0x30, tbs, ALG, SIGNATURE, SIGNATURE), "not a CertificateList");
    refuses(tlv(0x30, tlv(0x31, ALG, ISSUER, THIS), ALG, SIGNATURE), "not a CertificateList");
    refuses(tlv(0x30, tbs, tlv(0x31, OID_SHA256_RSA, NULL), SIGNATURE), "not a CertificateList");
    refuses(tlv(0x30, tbs, ALG, tlv(0x04, [0x00, 0xde])), "not a CertificateList");
    refuses(crlOf([ALG, ISSUER, THIS], ALG, tlv(0x03)), "signature BIT STRING has unused bits");
    refuses(crlOf([ALG, ISSUER, THIS], ALG, tlv(0x03, [0x01, 0xde])), "signature BIT STRING has unused bits");
    expect(parseCrlDer(crlOf([ALG, ISSUER, THIS], ALG, tlv(0x03, [0x00]))).signature).toHaveLength(0);
  });

  it("refuses a TBSCertList with a field missing, out of place or one too many", () => {
    refuses(crlOf([tlv(0x02, [0x01]), THIS, ISSUER]), "missing TBSCertList signature algorithm");
    refuses(crlOf([]), "missing TBSCertList signature algorithm");
    const sha1 = tlv(0x30, tlv(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]), NULL);
    refuses(crlOf([sha1, ISSUER, THIS]), "signature algorithm differs between TBSCertList and CertificateList");
    refuses(crlOf([tlv(0x30, OID_SHA256_RSA), ISSUER, THIS]), "signature algorithm differs between TBSCertList and CertificateList");
    refuses(crlOf([ALG, THIS]), "missing issuer");
    refuses(crlOf([ALG, tlv(0x31), THIS]), "missing issuer");
    refuses(crlOf([ALG, ISSUER]), "missing thisUpdate");
    refuses(crlOf([ALG, ISSUER, tlv(0x16, ascii("261107210000Z"))]), "missing thisUpdate");
    refuses(crlOf([ALG, ISSUER, THIS, NEXT, NEXT]), "unexpected field in TBSCertList");
    refuses(crlOf([ALG, ISSUER, THIS, tlv(0x02, [0x01])]), "unexpected field in TBSCertList");
    refuses(crlOf([ALG, ISSUER, THIS, tlv(0xa0, tlv(0x30)), tlv(0x30)]), "unexpected field in TBSCertList");
    refuses(crlOf([ALG, ISSUER, THIS, tlv(0xa0, tlv(0x30)), tlv(0xa0, tlv(0x30))]), "unexpected field in TBSCertList");
    // The extensions alone, with no entries and no nextUpdate, are a valid list.
    expect(parseCrlDer(crlOf([ALG, ISSUER, THIS, tlv(0xa0, tlv(0x30))])).entryCount).toBe(0);
  });

  it("refuses an entry that is not a serial number and a date", () => {
    const date = utc("261106120000Z");
    const withEntries = (...e: Uint8Array[]) => crlOf([ALG, ISSUER, THIS, tlv(0x30, ...e)]);
    // Where the list of entries begins: after the headers of the list, of the TBSCertList and of the entries.
    const head = String(crlOf([ALG, ISSUER, THIS, tlv(0x30)]).length - SIGNATURE.length - ALG.length);
    refuses(withEntries(tlv(0x31, tlv(0x02, [1]), date)), `revoked entry at ${head} is not a SEQUENCE`);
    refuses(withEntries(tlv(0x30, tlv(0x04, [1]), date)), `revoked entry at ${head} has no serial number`);
    refuses(withEntries(tlv(0x30, tlv(0x02), date)), `revoked entry at ${head} has no serial number`);
    // The date is read on lookup: the list parses, and asking for that serial is refused.
    const noDate = parseCrlDer(withEntries(entry([1], null), entry([2], date)));
    expect(noDate.entryCount).toBe(2);
    expect(noDate.entry("2")).toEqual({ revocationDate: new Date("2026-11-06T12:00:00Z") });
    expect(() => noDate.entry("1")).toThrow(DerError);
    const wrongDate = parseCrlDer(withEntries(tlv(0x30, tlv(0x02, [1]), tlv(0x02, [5]))));
    expect(() => wrongDate.entry("1")).toThrow(`entry at ${head} has no revocation date`);
    // The same serial twice is one entry, the last one.
    const twice = parseCrlDer(withEntries(entry([7], utc("261106120000Z")), entry([7], utc("261106130000Z"))));
    expect(twice.entryCount).toBe(1);
    expect(twice.entry("7")?.revocationDate.toISOString()).toBe("2026-11-06T13:00:00.000Z");
  });
});

describe("ecdsaDerToRaw", () => {
  const sig = (r: number[], s: number[]) => tlv(0x30, tlv(0x02, r), tlv(0x02, s));

  it("pads each integer to the size of the curve and drops the sign byte", () => {
    expect(hex(ecdsaDerToRaw(sig([0x01], [0x02]), 4))).toBe("0000000100000002");
    expect(hex(ecdsaDerToRaw(sig([0x00, 0xff, 0xee, 0xdd, 0xcc], [0x11, 0x22, 0x33, 0x44]), 4))).toBe("ffeeddcc11223344");
    expect(hex(ecdsaDerToRaw(sig([0x00, 0x00, 0x00, 0x00, 0x00, 0x05], [0x06]), 4))).toBe("0000000500000006");
  });

  it("refuses an integer longer than the curve and anything that is not two integers", () => {
    expect(() => ecdsaDerToRaw(sig([0x01, 0xff, 0xee, 0xdd, 0xcc], [0x02]), 4)).toThrow("bad ECDSA signature");
    expect(() => ecdsaDerToRaw(sig([0x01], [0x01, 0xff, 0xee, 0xdd, 0xcc]), 4)).toThrow("bad ECDSA signature");
    expect(() => ecdsaDerToRaw(tlv(0x30, tlv(0x02, [1])), 4)).toThrow("bad ECDSA signature");
    expect(() => ecdsaDerToRaw(tlv(0x30, tlv(0x04, [1]), tlv(0x02, [2])), 4)).toThrow("bad ECDSA signature");
    expect(() => ecdsaDerToRaw(tlv(0x30, tlv(0x02, [1]), tlv(0x04, [2])), 4)).toThrow("bad ECDSA signature");
    expect(() => ecdsaDerToRaw(Uint8Array.from([0x30]), 4)).toThrow(DerError);
  });
});
