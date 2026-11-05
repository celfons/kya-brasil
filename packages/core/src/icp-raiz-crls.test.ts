/// <reference types="node" /> // test-only: node:fs
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { verifyCrl } from "./revocation.js";

// Real CRLs of the AC Raiz chains, with the root certificate that signs each (research/crl-compat/fetch.py).
const fixtures = JSON.parse(readFileSync(new URL("./testdata/icp-raiz-crls.json", import.meta.url), "utf8")) as Record<string, { crl: string; issuer: string }>;
const der = (b64: string) => new Uint8Array(Buffer.from(b64, "base64"));
const check = (name: string) => verifyCrl({ crlDer: der(fixtures[name]!.crl), issuerCertificate: fixtures[name]!.issuer, pastNextUpdate: "accept" });

describe("real ICP-Brasil AC Raiz CRLs, by signature algorithm", () => {
  it("v3: ECDSA P-521 with SHA-512", async () => {
    await expect(check("raiz-v3")).resolves.toMatchObject({ this_update: expect.any(String) });
  });

  it("v6: Ed448 (also AC INMETRO)", async () => {
    await expect(check("raiz-v6")).resolves.toMatchObject({ this_update: expect.any(String) });
  });

  it("v6 tampered: a flipped byte in the CRL extensions breaks the Ed448 signature", async () => {
    const crl = der(fixtures["raiz-v6"]!.crl);
    crl[249] = crl[249]! ^ 1; // last byte of TBSCertList (authorityKeyIdentifier): structure intact
    await expect(verifyCrl({ crlDer: crl, issuerCertificate: fixtures["raiz-v6"]!.issuer, pastNextUpdate: "accept" })).rejects.toThrow(/CRL signature does not match/);
  });

  it("a corrupted issuer Name is refused as REVOCATION_UNAVAILABLE, not with a raw parser error", async () => {
    const crl = der(fixtures["raiz-v6"]!.crl);
    crl[30] = crl[30]! ^ 1; // a length inside the issuer Name
    await expect(verifyCrl({ crlDer: crl, issuerCertificate: fixtures["raiz-v6"]!.issuer, pastNextUpdate: "accept" })).rejects.toMatchObject({ code: "REVOCATION_UNAVAILABLE" });
  });

  it("v4: ECDSA on brainpoolP512r1 with explicit parameters is refused as unsupported, not as a bad signature", async () => {
    await expect(check("raiz-v4")).rejects.toThrow(/ECDSA on curve given by explicit parameters\) is not supported/);
  });

  it("v7: id-Ed521 (1.3.6.1.4.1.44588.2.1) is refused as unsupported", async () => {
    await expect(check("raiz-v7")).rejects.toThrow(/1\.3\.6\.1\.4\.1\.44588\.2\.1 is not supported/);
  });
});
