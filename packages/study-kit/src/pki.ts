// =====================================================================================================
//  TEST ONLY. The PKI made here is WORTHLESS: a throwaway "ICP-Brasil-like" hierarchy made up on the spot, with
//  fake CNPJ / CPF numbers and a password in clear text. No real verifier trusts it. Same construction as
//  examples/quickstart/make-test-pki.mjs, plus the issuing AC's key kept aside so the kit can publish new CRLs
//  (task T4 revokes the company certificate).
// =====================================================================================================
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import forge from "node-forge";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { OID_ICP_CNPJ, OID_ICP_PERSON } from "@kya-brasil/core";

x509.cryptoProvider.set(globalThis.crypto);

export const TEST_PASSWORD = "somente-teste-1234";
/** The participant's company ("ACME LTDA TESTE"), which signs the mandate. */
export const COMPANY_CNPJ = "11222333000181";
export const REPRESENTATIVE_CPF = "52998224725";
/** Serial number (hex) of the company's e-CNPJ: the one T4 revokes. */
export const COMPANY_SERIAL = "1001";
export const CRL_URL = "https://lcr.exemplo.invalid/ac-teste-sem-valor.crl";
export const WARNING = "SOMENTE TESTE / TEST ONLY - PKI descartavel gerada pelo kya-study, SEM VALOR. Nunca confie nela.";

const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 } as const;
const DAY = 86_400_000;

export const pem = (der: ArrayBuffer | Uint8Array, label: string) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der as ArrayBuffer).toString("base64").replace(/(.{64})/g, "$1\n").trim()}\n-----END ${label}-----\n`;
export const pemBlocks = (text: string) => text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];

const keys = () => crypto.subtle.generateKey(alg, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;

/** Everything the kit writes for the participant (pki/) and keeps for itself (.kya-study/pki-ac.json). */
export interface TestPki {
  anchorsPem: string;
  crlDer: Uint8Array;
  companyPfx: Uint8Array;
  representativePfx: Uint8Array;
  agent: { kind: "evm"; id: `0x${string}`; privateKey: `0x${string}` };
  /** Kept by the kit only: the issuing AC's certificate and PKCS#8 key, to publish new CRLs. */
  ac: { certificatePem: string; privateKeyPkcs8: string };
}

export async function makeTestPki(now = new Date()): Promise<TestPki> {
  const t = now.getTime();
  const notBefore = new Date(t - DAY);
  const rootKeys = await keys();
  const root = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01", name: "CN=AC Raiz TESTE SEM VALOR, O=ICP-Brasil TESTE, C=BR", notBefore, notAfter: new Date(t + 3650 * DAY),
    signingAlgorithm: alg, keys: rootKeys,
    extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)]
  });
  const acKeys = await keys();
  const ac = await x509.X509CertificateGenerator.create({
    serialNumber: "02", subject: "CN=AC TESTE SEM VALOR v1, O=ICP-Brasil TESTE, C=BR", issuer: root.subject, notBefore, notAfter: new Date(t + 1825 * DAY),
    signingAlgorithm: alg, publicKey: acKeys.publicKey, signingKey: rootKeys.privateKey,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)]
  });

  const otherName = (oid: string, text: string) => new OtherName({ typeId: oid, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(text))) });
  async function leaf(serial: string, subject: string, on: OtherName) {
    const k = await keys();
    const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: on })])));
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: serial, subject, issuer: ac.subject, notBefore, notAfter: new Date(t + 365 * DAY),
      signingAlgorithm: alg, publicKey: k.publicKey, signingKey: acKeys.privateKey,
      extensions: [san, new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true), new x509.CRLDistributionPointsExtension([CRL_URL])]
    });
    return { cert, keys: k };
  }
  const company = await leaf(COMPANY_SERIAL, `CN=ACME LTDA TESTE:${COMPANY_CNPJ}, O=ICP-Brasil TESTE, C=BR`, otherName(OID_ICP_CNPJ, COMPANY_CNPJ));
  const person = await leaf("1002", `CN=FULANA DE TESTE:${REPRESENTATIVE_CPF}, O=ICP-Brasil TESTE, C=BR`, otherName(OID_ICP_PERSON, `01011990${REPRESENTATIVE_CPF}${"0".repeat(29)}`));

  async function pfx(l: { cert: x509.X509Certificate; keys: CryptoKeyPair }) {
    const key = forge.pki.privateKeyFromPem(pem(await crypto.subtle.exportKey("pkcs8", l.keys.privateKey), "PRIVATE KEY"));
    const chain = [l.cert, ac, root].map((c) => forge.pki.certificateFromPem(pem(c.rawData, "CERTIFICATE")));
    const p12 = forge.pkcs12.toPkcs12Asn1(key, chain, TEST_PASSWORD, { algorithm: "aes256" });
    return new Uint8Array(Buffer.from(forge.asn1.toDer(p12).getBytes(), "binary"));
  }

  const acState = { certificatePem: pem(ac.rawData, "CERTIFICATE"), privateKeyPkcs8: Buffer.from(await crypto.subtle.exportKey("pkcs8", acKeys.privateKey)).toString("base64") };
  const crlDer = await makeCrl(acState, { thisUpdate: new Date(t - 60_000), nextUpdate: new Date(t + 7 * DAY), revokeCompany: false });
  const privateKey = generatePrivateKey();
  return {
    anchorsPem: pem(root.rawData, "CERTIFICATE") + pem(ac.rawData, "CERTIFICATE"),
    crlDer,
    companyPfx: await pfx(company),
    representativePfx: await pfx(person),
    agent: { kind: "evm", id: privateKeyToAccount(privateKey).address, privateKey },
    ac: acState
  };
}

/**
 * A CRL of the test AC. It always lists one made-up serial (so a lookup is a real one); with `revokeCompany` it also
 * lists the company's e-CNPJ (key compromise), which is how the kit "revokes" the certificate in T4.
 */
export async function makeCrl(acState: TestPki["ac"], p: { thisUpdate: Date; nextUpdate: Date; revokeCompany: boolean; revokedAt?: Date; revokeOthers?: string[] }): Promise<Uint8Array> {
  const ac = new x509.X509Certificate(acState.certificatePem);
  const signingKey = await crypto.subtle.importKey("pkcs8", Buffer.from(acState.privateKeyPkcs8, "base64"), { name: alg.name, hash: alg.hash }, false, ["sign"]);
  const entries: { serialNumber: string; revocationDate: Date; reason: x509.X509CrlReason }[] = [
    { serialNumber: "0bad", revocationDate: new Date(p.thisUpdate.getTime() - DAY), reason: x509.X509CrlReason.keyCompromise }
  ];
  for (const serialNumber of p.revokeOthers ?? []) entries.push({ serialNumber, revocationDate: p.thisUpdate, reason: x509.X509CrlReason.keyCompromise });
  if (p.revokeCompany) entries.push({ serialNumber: COMPANY_SERIAL, revocationDate: p.revokedAt ?? p.thisUpdate, reason: x509.X509CrlReason.keyCompromise });
  const crl = await x509.X509CrlGenerator.create({ issuer: ac.subject, thisUpdate: p.thisUpdate, nextUpdate: p.nextUpdate, signingAlgorithm: alg, signingKey, entries });
  return new Uint8Array(crl.rawData);
}
