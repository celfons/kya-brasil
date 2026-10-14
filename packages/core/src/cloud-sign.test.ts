/// <reference types="node" />
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import forge from "node-forge";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { OID_ICP_CNPJ, verifyIcpSignature } from "./icp-brasil.js";
import { cloudSigner, isProviderId, newState, pkcePair, type CloudSignatureProvider } from "./cloud-sign.js";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");

/** A stand-in PSC: holds the key, signs hashes with raw RSA over DigestInfo, as PSC "raw" signature APIs do. */
async function mockPsc() {
  const caKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const other = new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode("11222333000181"))) });
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
  const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "02", subject: "CN=ACME LTDA:11222333000181, O=ICP-Brasil, C=BR", issuer: ca.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: caKeys.privateKey, extensions: [san] });
  // The PSC signs a SHA-256 hash with raw PKCS#1 v1.5 (DigestInfo + hash), the key never leaving it.
  const pem = `-----BEGIN PRIVATE KEY-----\n${b64(await crypto.subtle.exportKey("pkcs8", keys.privateKey))}\n-----END PRIVATE KEY-----`;
  const pscKey = forge.pki.privateKeyFromPem(pem) as forge.pki.rsa.PrivateKey;
  const signHashRaw = (hash: Uint8Array) => {
    const md = { algorithm: "sha256", digest: () => forge.util.createBuffer(forge.util.binary.raw.encode(hash)) } as unknown as forge.md.MessageDigest;
    return new Uint8Array(forge.util.binary.raw.decode(pscKey.sign(md)));
  };
  const codes = new Map<string, { challenge: string }>();
  const provider: CloudSignatureProvider = {
    id: "mock-psc",
    name: "PSC de teste",
    authorizationUrl: ({ redirectUri, state, codeChallenge }) => {
      const code = `code-${codes.size + 1}`;
      codes.set(code, { challenge: codeChallenge });
      return `${redirectUri}?code=${code}&state=${state}`;
    },
    async exchangeCode({ code, codeVerifier }) {
      const c = codes.get(code);
      const expected = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier))).toString("base64url");
      if (!c || c.challenge !== expected) throw new Error("PKCE mismatch");
      codes.delete(code);
      return {
        certificates: async () => [new Uint8Array(leaf.rawData), new Uint8Array(ca.rawData)],
        signHash: async (hash) => {
          if (hash.length !== 32) throw new Error("expected a SHA-256 hash");
          return signHashRaw(hash);
        }
      };
    }
  };
  return { provider, ca };
}

describe("cloud e-CNPJ through a provider interface (D-28)", () => {
  it("PKCE pairs and states are random and well formed", async () => {
    const a = await pkcePair();
    const b = await pkcePair();
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(newState()).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(isProviderId("my-psc")).toBe(true);
    expect(isProviderId("../x")).toBe(false);
  });

  it("authorize, exchange with PKCE, sign: the issuer accepts the CMS", async () => {
    const { provider, ca } = await mockPsc();
    const { verifier, challenge } = await pkcePair();
    const back = new URL(await provider.authorizationUrl({ redirectUri: "http://127.0.0.1:9/cb", state: "s1", codeChallenge: challenge }));
    expect(back.searchParams.get("state")).toBe("s1");
    await expect(provider.exchangeCode({ code: back.searchParams.get("code")!, redirectUri: "http://127.0.0.1:9/cb", codeVerifier: "wrong" })).rejects.toThrow(/PKCE/);
    const back2 = new URL(await provider.authorizationUrl({ redirectUri: "http://127.0.0.1:9/cb", state: "s2", codeChallenge: challenge }));
    const session = await provider.exchangeCode({ code: back2.searchParams.get("code")!, redirectUri: "http://127.0.0.1:9/cb", codeVerifier: verifier });
    const signer = await cloudSigner(session);
    expect(signer.cnpj).toBe("11222333000181");
    const text = "KYA Brasil: prove this agent key acts for a company\ncnpj: 11222333000181";
    const cms = await signer.sign(text);
    const proof = await verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: "11222333000181", anchors: [b64(ca.rawData)], now: new Date("2026-10-14T00:00:00Z") });
    expect(proof.cnpj).toBe("11222333000181");
  });
});
