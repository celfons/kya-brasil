import { afterEach, describe, expect, it, vi } from "vitest";
import { certificateRevocation, resetCrlMemory } from "./revocation"; // loads reflect-metadata (via core) before x509
import * as x509 from "@peculiar/x509";
import type { AppEnv } from "./env";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");

async function acWithCrl(revokedSerial: string) {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste, O=ICP-Brasil, C=BR", notBefore: new Date("2020-01-01"), notAfter: new Date("2040-01-01"), signingAlgorithm: alg, keys });
  const crl = await x509.X509CrlGenerator.create({ issuer: cert.subject, thisUpdate: new Date(Date.now() - 3600_000), nextUpdate: new Date(Date.now() + 86400_000), signingAlgorithm: alg, signingKey: keys.privateKey, entries: [{ serialNumber: revokedSerial, revocationDate: new Date(Date.now() - 1800_000), reason: x509.X509CrlReason.keyCompromise }] });
  return { issuer_certificate: b64(cert.rawData), crl: crl.rawData };
}

function kvEnv() {
  const kv = new Map<string, ArrayBuffer>();
  const puts: string[] = [];
  const env = {
    CACHE: {
      get: async (k: string) => kv.get(k) ?? null,
      put: async (k: string, v: ArrayBuffer) => { kv.set(k, v); puts.push(k); }
    }
  } as unknown as AppEnv;
  return { env, puts };
}

afterEach(() => {
  vi.unstubAllGlobals();
  resetCrlMemory();
});

describe("CRL fetch for the e-CNPJ", () => {
  it("falls back to the next distribution point, caches the CRL once and finds the serial", async () => {
    const { issuer_certificate, crl } = await acWithCrl("0abc");
    const fetched: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      fetched.push(url);
      return url.includes("down") ? new Response("x", { status: 503 }) : new Response(crl);
    });
    const { env, puts } = kvEnv();
    const cert = { serial_number: "abc", issuer_certificate, crl_urls: ["http://down.ac/lcr.crl", "http://ok.ac/lcr.crl"] };
    const r = await certificateRevocation(env, cert);
    expect(r).toMatchObject({ revoked: true, reason: "keyCompromise" });
    expect(fetched).toEqual(["http://down.ac/lcr.crl", "http://ok.ac/lcr.crl"]);
    expect(puts).toEqual(["crl:http://ok.ac/lcr.crl"]);
    // Second check (other certificate, same AC): served from memory, no download, no KV write.
    const clean = await certificateRevocation(env, { ...cert, serial_number: "0def" });
    expect(clean.revoked).toBe(false);
    expect(fetched).toHaveLength(3); // only the failing URL was tried again
    expect(puts).toHaveLength(1);
  });

  it("fails closed when no CRL can be trusted", async () => {
    const { issuer_certificate } = await acWithCrl("01");
    vi.stubGlobal("fetch", async () => new Response(new Uint8Array([1, 2, 3])));
    const { env } = kvEnv();
    await expect(certificateRevocation(env, { serial_number: "01", issuer_certificate, crl_urls: ["http://bad.ac/lcr.crl"] })).rejects.toMatchObject({ code: "REVOCATION_UNAVAILABLE" });
    await expect(certificateRevocation(env, { serial_number: "01", issuer_certificate: null, crl_urls: ["http://ok.ac/lcr.crl"] })).rejects.toThrow(/anchors/);
    await expect(certificateRevocation(env, { serial_number: "01", issuer_certificate, crl_urls: [] })).rejects.toThrow(/distribution point/);
  });
});
