// =====================================================================================================
//  TEST ONLY. Everything this script writes is WORTHLESS: a throwaway "ICP-Brasil-like" PKI made up on the
//  spot, with fake CNPJ / CPF numbers and passwords in clear text. No real verifier trusts it, and you must
//  never add out/anchors.pem to a real trust store. Real ICP-Brasil anchors: anchors/icp-brasil.pem.
// =====================================================================================================
//
// Writes to ./out (or the directory in KYA_QUICKSTART_OUT):
//   anchors.pem         root + intermediate AC (the "trust anchors" bundle, same format as anchors/icp-brasil.pem)
//   ac.crl              DER CRL of the intermediate AC (revokes nothing but a made-up serial), nextUpdate in 7 days
//   company.pfx         e-CNPJ A1 file of "ACME LTDA" (CNPJ 11.222.333/0001-81), password in pki.json
//   representative.pfx  e-CPF A1 file of a legal representative (CPF 529.982.247-25), password in pki.json
//   agent.json          the agent's EVM key (private key in clear: test only)
//   pki.json            the numbers above, for the other scripts
//
// The certificates carry the ICP-Brasil otherName fields that @kya-brasil/core reads (packages/core/src/icp-brasil.ts):
// 2.16.76.1.3.3 (CNPJ) on the e-CNPJ and 2.16.76.1.3.1 (birth date + CPF) on the e-CPF.
import "reflect-metadata";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import forge from "node-forge";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { OID_ICP_CNPJ, OID_ICP_PERSON } from "@kya-brasil/core";

x509.cryptoProvider.set(globalThis.crypto);
const OUT = resolve(process.env.KYA_QUICKSTART_OUT ?? join(import.meta.dirname, "out"));
const PASSWORD = "test-only-1234";
const CNPJ = "11222333000181";
const CPF = "52998224725";
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const day = 86_400_000;
const now = Date.now();
const notBefore = new Date(now - day);
const pem = (der, label) => `-----BEGIN ${label}-----\n${Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n").trim()}\n-----END ${label}-----\n`;
const keys = () => crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
const crlUrl = "https://crl.example.invalid/ac-teste.crl"; // never fetched: the scripts read out/ac.crl

const rootKeys = await keys();
const root = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01", name: "CN=AC Raiz TESTE SEM VALOR, O=ICP-Brasil TESTE, C=BR", notBefore, notAfter: new Date(now + 3650 * day),
  signingAlgorithm: alg, keys: rootKeys,
  extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)]
});
const acKeys = await keys();
const ac = await x509.X509CertificateGenerator.create({
  serialNumber: "02", subject: "CN=AC TESTE SEM VALOR v1, O=ICP-Brasil TESTE, C=BR", issuer: root.subject, notBefore, notAfter: new Date(now + 1825 * day),
  signingAlgorithm: alg, publicKey: acKeys.publicKey, signingKey: rootKeys.privateKey,
  extensions: [new x509.BasicConstraintsExtension(true, 0, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)]
});

async function leaf(serial, subject, otherName) {
  const k = await keys();
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName })])));
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial, subject, issuer: ac.subject, notBefore, notAfter: new Date(now + 365 * day),
    signingAlgorithm: alg, publicKey: k.publicKey, signingKey: acKeys.privateKey,
    extensions: [san, new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true), new x509.CRLDistributionPointsExtension([crlUrl])]
  });
  return { cert, keys: k };
}
const otherName = (oid, text) => new OtherName({ typeId: oid, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(text))) });

const company = await leaf("1001", `CN=ACME LTDA TESTE:${CNPJ}, O=ICP-Brasil TESTE, C=BR`, otherName(OID_ICP_CNPJ, CNPJ));
// 2.16.76.1.3.1: ddmmaaaa birth date, 11-digit CPF, then NIS/RG fields (zeros here).
const person = await leaf("1002", `CN=FULANA DE TESTE:${CPF}, O=ICP-Brasil TESTE, C=BR`, otherName(OID_ICP_PERSON, `01011990${CPF}${"0".repeat(29)}`));

async function pfx(l) {
  const key = forge.pki.privateKeyFromPem(pem(await crypto.subtle.exportKey("pkcs8", l.keys.privateKey), "PRIVATE KEY"));
  const chain = [l.cert, ac, root].map((c) => forge.pki.certificateFromPem(pem(c.rawData, "CERTIFICATE")));
  const p12 = forge.pkcs12.toPkcs12Asn1(key, chain, PASSWORD, { algorithm: "aes256" });
  return Buffer.from(forge.asn1.toDer(p12).getBytes(), "binary");
}

// The AC's CRL: one made-up revoked serial, so the lookup is a real one; our leaves are not on it.
const crl = await x509.X509CrlGenerator.create({
  issuer: ac.subject, thisUpdate: new Date(now - 60_000), nextUpdate: new Date(now + 7 * day), signingAlgorithm: alg, signingKey: acKeys.privateKey,
  entries: [{ serialNumber: "0bad", revocationDate: new Date(now - day), reason: x509.X509CrlReason.keyCompromise }]
});

const agentKey = generatePrivateKey();
const agentAddress = privateKeyToAccount(agentKey).address;

mkdirSync(OUT, { recursive: true });
const warning = "TEST ONLY - throwaway PKI generated by examples/quickstart/make-test-pki.mjs - WORTHLESS, never trust it";
writeFileSync(join(OUT, "README.txt"), `${warning}\n`);
writeFileSync(join(OUT, "anchors.pem"), pem(root.rawData, "CERTIFICATE") + pem(ac.rawData, "CERTIFICATE"));
writeFileSync(join(OUT, "ac.crl"), Buffer.from(crl.rawData));
writeFileSync(join(OUT, "company.pfx"), await pfx(company));
writeFileSync(join(OUT, "representative.pfx"), await pfx(person));
writeFileSync(join(OUT, "agent.json"), JSON.stringify({ warning, kind: "evm", id: agentAddress, privateKey: agentKey }, null, 2));
writeFileSync(join(OUT, "pki.json"), JSON.stringify({ warning, password: PASSWORD, cnpj: CNPJ, representative_cpf: CPF, crl_url: crlUrl }, null, 2));
console.log(`TEST ONLY: throwaway PKI written to ${OUT} (worthless, never trust it)`);
