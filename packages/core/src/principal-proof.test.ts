/// <reference types="node" />
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import * as pkijs from "pkijs";
import { challengeText } from "./challenge.js";
import { buildCredential, buildPersonCredential, mandateSha256 } from "./credential.js";
import { OID_ICP_CNPJ, OID_ICP_PERSON, verifyIcpSignature } from "./icp-brasil.js";
import { validateMandate } from "./mandate.js";
import { personChallengeText } from "./person.js";
import { decodePrincipalProofHeader, encodePrincipalProofHeader, verifyPrincipalProof } from "./principal-proof.js";
import type { AgentKey, Mandate } from "./types.js";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const CNPJ = "11222333000181";
const CPF = "52998224725";
const ISSUER = "https://kya.test";
const now = new Date("2026-10-14T00:00:00Z");
const agent: AgentKey = { kind: "evm", id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" };
const mandate: Mandate = validateMandate({ actions: ["buy"], max_per_operation: { amount: 500, currency: "BRL" } });

async function ca() {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  return { keys, cert };
}

async function leaf(root: Awaited<ReturnType<typeof ca>>, kind: "company" | "person", serial = "02") {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const other = kind === "person"
    ? new OtherName({ typeId: OID_ICP_PERSON, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(`01011990${CPF}00000000000000000000000000000`))) })
    : new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(CNPJ))) });
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
  const subject = kind === "person" ? `CN=MARIA DA SILVA:${CPF}, O=ICP-Brasil, C=BR` : `CN=ACME LTDA:${CNPJ}, O=ICP-Brasil, C=BR`;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: serial, subject, issuer: root.cert.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: root.keys.privateKey, extensions: [san] });
  return { keys, cert };
}

async function cms(signer: Awaited<ReturnType<typeof leaf>>, root: Awaited<ReturnType<typeof ca>>, text: string) {
  pkijs.setEngine("t", new pkijs.CryptoEngine({ name: "t", crypto: globalThis.crypto as Crypto }));
  const lp = pkijs.Certificate.fromBER(signer.cert.rawData);
  const signed = new pkijs.SignedData({ version: 1, encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: "1.2.840.113549.1.7.1" }), signerInfos: [new pkijs.SignerInfo({ version: 1, sid: new pkijs.IssuerAndSerialNumber({ issuer: lp.issuer, serialNumber: lp.serialNumber }) })], certificates: [lp, pkijs.Certificate.fromBER(root.cert.rawData)] });
  await signed.sign(signer.keys.privateKey, 0, "SHA-256", new TextEncoder().encode(text).buffer as ArrayBuffer);
  return b64(new pkijs.ContentInfo({ contentType: "1.2.840.113549.1.7.2", content: signed.toSchema(true) }).toSchema().toBER(false));
}

/** A company credential issued from a signed challenge, the way the issuer does it. */
async function companyCase(m: Mandate = mandate) {
  const root = await ca();
  const signer = await leaf(root, "company");
  const mandate_sha256 = await mandateSha256(m);
  const text = challengeText({ issuer: ISSUER, challenge_id: "c-1", agent, cnpj: CNPJ, mandate_sha256, expires_at: "2026-10-14T00:15:00.000Z" });
  const sig = await cms(signer, root, text);
  const icp = await verifyIcpSignature({ cmsBase64: sig, challenge: text, expectedCnpj: CNPJ, anchors: [b64(root.cert.rawData)], now });
  const credential = buildCredential({ credential_id: "cred-1", agent, cnpj: CNPJ, legal_name: "ACME LTDA", registration_status: "ATIVA", certificate: { sha256: icp.certificate_sha256, subject: icp.certificate_subject, issuer: icp.issuer, signed_at: icp.signed_at, not_after: icp.not_after }, mandate: m, mandate_sha256, ttl_seconds: 90 * 86400, issuer: ISSUER, now });
  return { root, signer, text, sig, credential, anchors: [b64(root.cert.rawData)] };
}

const failed = (r: Awaited<ReturnType<typeof verifyPrincipalProof>>) => r.checks.filter((c) => !c.ok).map((c) => c.rule);

describe("verification without trusting the issuer (D-34)", () => {
  it("accepts the principal's own signature over this agent and this mandate, and returns what the CRL check needs", async () => {
    const k = await companyCase();
    const r = await verifyPrincipalProof({ credential: k.credential, proof: { text: k.text, cms: k.sig }, anchors: k.anchors, now });
    expect(failed(r)).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.revocation).toMatchObject({ serial_number: "2" });
  });

  it("refuses a credential whose mandate is not the one signed", async () => {
    const k = await companyCase();
    const wider = { ...k.credential, mandate: { ...k.credential.mandate, max_per_operation: { amount: 50_000, currency: "BRL" } } };
    expect(failed(await verifyPrincipalProof({ credential: wider, proof: { text: k.text, cms: k.sig }, anchors: k.anchors, now }))).toEqual(["mandate"]);
  });

  it("refuses a proof for another agent or another issuer", async () => {
    const k = await companyCase();
    const otherAgent = { ...k.credential, agent: { kind: "evm" as const, id: "0x0000000000000000000000000000000000000001" } };
    expect(failed(await verifyPrincipalProof({ credential: otherAgent, proof: { text: k.text, cms: k.sig }, anchors: k.anchors, now }))).toEqual(["agent"]);
    const otherIssuer = { ...k.credential, issuer: "https://another.issuer" };
    expect(failed(await verifyPrincipalProof({ credential: otherIssuer, proof: { text: k.text, cms: k.sig }, anchors: k.anchors, now }))).toEqual(["issuer"]);
  });

  it("refuses another certificate of the same company than the one the credential records", async () => {
    const k = await companyCase();
    const second = await leaf(k.root, "company", "03");
    const sig = await cms(second, k.root, k.text);
    expect(failed(await verifyPrincipalProof({ credential: k.credential, proof: { text: k.text, cms: sig }, anchors: k.anchors, now }))).toEqual(["certificate"]);
  });

  it("refuses a signature over a different text, untrusted anchors and a text without the mandate hash", async () => {
    const k = await companyCase();
    expect(failed(await verifyPrincipalProof({ credential: k.credential, proof: { text: k.text + "\nx", cms: k.sig }, anchors: k.anchors, now }))).toContain("signature");
    const stranger = await ca();
    expect(failed(await verifyPrincipalProof({ credential: k.credential, proof: { text: k.text, cms: k.sig }, anchors: [b64(stranger.cert.rawData)], now }))).toContain("signature");
    const old = k.text.split("\n").filter((l) => !l.startsWith("mandate-sha256: ")).join("\n");
    const oldSig = await cms(k.signer, k.root, old);
    expect(failed(await verifyPrincipalProof({ credential: k.credential, proof: { text: old, cms: oldSig }, anchors: k.anchors, now }))).toEqual(["mandate"]);
  });

  it("works for natural persons, and returns nothing personal", async () => {
    const root = await ca();
    const signer = await leaf(root, "person");
    const mandate_sha256 = await mandateSha256(mandate);
    const text = personChallengeText({ issuer: ISSUER, challenge_id: "c-2", agent, mandate_sha256, expires_at: "2026-10-14T00:15:00.000Z" });
    const sig = await cms(signer, root, text);
    const certificate_sha256 = Buffer.from(await crypto.subtle.digest("SHA-256", signer.cert.rawData)).toString("hex");
    const credential = buildPersonCredential({ credential_id: "cred-2", agent, certificate: { sha256: certificate_sha256, issuer: root.cert.subject, signed_at: now.toISOString(), not_after: signer.cert.notAfter.toISOString() }, mandate, mandate_sha256, ttl_seconds: 90 * 86400, issuer: ISSUER, now });
    const r = await verifyPrincipalProof({ credential, proof: { text, cms: sig }, anchors: [b64(root.cert.rawData)], now });
    expect(failed(r)).toEqual([]);
    expect(JSON.stringify(r)).not.toContain(CPF);
    expect(JSON.stringify(r)).not.toContain("MARIA");
  });

  it("never throws on malformed input and fails closed", async () => {
    const k = await companyCase();
    expect((await verifyPrincipalProof({ credential: k.credential, proof: { text: k.text, cms: "not-base64" }, anchors: k.anchors, now })).ok).toBe(false);
    expect((await verifyPrincipalProof({ credential: k.credential, proof: null as never, anchors: k.anchors, now })).ok).toBe(false);
    expect((await verifyPrincipalProof({ credential: k.credential, proof: { text: k.text, cms: k.sig }, anchors: k.anchors, now: new Date(Number.NaN) })).ok).toBe(false);
  });

  it("header round trip", async () => {
    const k = await companyCase();
    expect(decodePrincipalProofHeader(encodePrincipalProofHeader({ text: k.text, cms: k.sig }))).toEqual({ text: k.text, cms: k.sig });
    expect(() => decodePrincipalProofHeader("@@@")).toThrow(/KYA-Principal-Proof/);
  });
});
