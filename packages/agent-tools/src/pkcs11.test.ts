/// <reference types="node" />
/**
 * A3 path against a real PKCS#11 module: SoftHSM2, a software token with the same interface as the vendor
 * drivers. Runs when softhsm2-util and pkcs11-tool are installed (apt install softhsm2 opensc); skipped otherwise.
 */
import "reflect-metadata";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { OID_ICP_CNPJ, verifyIcpSignature } from "@kya-brasil/core";
import { listTokenCertificates, openToken } from "./pkcs11";

const LIB = ["/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"].find((p) => existsSync(p));
const hasTools = (() => {
  try {
    createRequire(import.meta.url)("pkcs11js");
    execFileSync("softhsm2-util", ["--version"], { stdio: "ignore" });
    execFileSync("which", ["pkcs11-tool"], { stdio: "ignore" });
    return !!LIB;
  } catch {
    return false;
  }
})();

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");

describe.skipIf(!hasTools)("e-CNPJ A3 through PKCS#11 (SoftHSM2)", () => {
  it("signs on the token; the issuer accepts it; wrong PIN is refused", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kya-p11-"));
    writeFileSync(join(dir, "softhsm2.conf"), `directories.tokendir = ${dir}\nobjectstore.backend = file\n`);
    process.env.SOFTHSM2_CONF = join(dir, "softhsm2.conf");
    execFileSync("softhsm2-util", ["--init-token", "--free", "--label", "kya-test", "--pin", "1234", "--so-pin", "5678"], { stdio: "ignore" });

    const caKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
    const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)] });
    const leafKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
    const other = new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode("11222333000181"))) });
    const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
    const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "02", subject: "CN=ACME LTDA:11222333000181, O=ICP-Brasil, C=BR", issuer: ca.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, publicKey: leafKeys.publicKey, signingKey: caKeys.privateKey, extensions: [san, new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true)] });
    writeFileSync(join(dir, "key.der"), Buffer.from(await crypto.subtle.exportKey("pkcs8", leafKeys.privateKey)));
    writeFileSync(join(dir, "leaf.der"), Buffer.from(leaf.rawData));
    writeFileSync(join(dir, "ca.der"), Buffer.from(ca.rawData));
    const tool = (...a: string[]) => execFileSync("pkcs11-tool", ["--module", LIB!, "--login", "--pin", "1234", ...a], { stdio: "ignore" });
    tool("--write-object", join(dir, "key.der"), "--type", "privkey", "--id", "01", "--label", "ecnpj");
    tool("--write-object", join(dir, "leaf.der"), "--type", "cert", "--id", "01", "--label", "ecnpj");
    tool("--write-object", join(dir, "ca.der"), "--type", "cert", "--id", "02", "--label", "ac");

    const listed = await listTokenCertificates({ library: LIB! });
    expect(listed.map((c) => [c.label, c.cnpj])).toEqual(expect.arrayContaining([["ecnpj", "11222333000181"], ["ac", null]]));

    const token = await openToken({ library: LIB!, pin: "1234" });
    try {
      expect(token.cnpj).toBe("11222333000181");
      const text = "KYA Brasil: prove this agent key acts for a company\ncnpj: 11222333000181";
      const cms = await token.sign(text);
      const proof = await verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: "11222333000181", anchors: [b64(ca.rawData)], now: new Date("2026-10-14T00:00:00Z") });
      expect(proof.cnpj).toBe("11222333000181");
    } finally {
      token.close();
    }
    await expect(openToken({ library: LIB!, pin: "0000" })).rejects.toThrow();
  });
});
