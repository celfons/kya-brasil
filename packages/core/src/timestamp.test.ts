/// <reference types="node" /> // test-only: Buffer, node:fs
/**
 * Time-stamp on the principal's signature (SPEC section 23): the request, a token accepted, and every way a token
 * is refused. The authority here is a throwaway one built at run time, never a real time-stamping authority.
 */
import "reflect-metadata";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { privateKeyToAccount } from "viem/accounts";
import { ecnpjSigner } from "./ecnpj-sign.js";
import { OID_ICP_CNPJ } from "./icp-brasil.js";
import { type MandateInput, addTimestamp, assembleCredential, buildMandate, mandateSigningInput, verifySelfIssuedCredential } from "./issuance.js";
import { decodePrincipalProofHeader, encodePrincipalProofHeader } from "./principal-proof.js";
import { revocationEffect } from "./revocation.js";
import { OID_KP_TIMESTAMPING, OID_SIGNATURE_TIMESTAMP, OID_TST_INFO, checkTimestamp, embeddedTimestamp, timestampRequest, verifyTimestamp } from "./timestamp.js";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const RSA = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const ab = (u: Uint8Array) => u.slice().buffer as ArrayBuffer;
const SIGNED = new Date("2026-11-04T12:00:00Z"); // when the principal signs and the authority stamps
const NOW = new Date("2026-11-10T12:00:00Z"); // when the verifier looks
const AGENT = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const CNPJ = "11222333000181";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";

type Party = { keys: CryptoKeyPair; cert: x509.X509Certificate };
const newKeys = async () => (await crypto.subtle.generateKey(RSA, true, ["sign", "verify"])) as CryptoKeyPair;
async function root(name: string): Promise<Party> {
  const keys = await newKeys();
  return { keys, cert: await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name, notBefore: new Date("2026-01-01"), notAfter: new Date("2031-01-01"), signingAlgorithm: RSA, keys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] }) };
}
async function issue(ca: Party, subject: string, serialNumber: string, extensions: x509.Extension[], dates: { from?: Date; to?: Date } = {}): Promise<Party> {
  const keys = await newKeys();
  return { keys, cert: await x509.X509CertificateGenerator.create({ serialNumber, subject, issuer: ca.cert.subject, notBefore: dates.from ?? new Date("2026-01-01"), notAfter: dates.to ?? new Date("2028-01-01"), signingAlgorithm: RSA, publicKey: keys.publicKey, signingKey: ca.keys.privateKey, extensions }) };
}
/** A time-stamping authority's certificate; `usages` and `critical` are what the refusal cases vary. */
const authority = (ca: Party, serial: string, usages: string[] = [OID_KP_TIMESTAMPING], critical = true, dates = {}) =>
  issue(ca, "CN=ACT Teste, O=ICP-Brasil, C=BR", serial, usages.length ? [new x509.ExtendedKeyUsageExtension(usages, critical)] : [], dates);

/** An RFC 3161 token over `stamped`, signed by `tsa`: SignedData whose content is the TSTInfo. */
async function stamp(tsa: Party, ca: Party, stamped: Uint8Array, genTime: Date): Promise<string> {
  const tst = new pkijs.TSTInfo({
    version: 1,
    policy: "2.16.76.1.6.6",
    messageImprint: new pkijs.MessageImprint({ hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 }), hashedMessage: new asn1js.OctetString({ valueHex: await crypto.subtle.digest("SHA-256", ab(stamped)) }) }),
    serialNumber: new asn1js.Integer({ value: 7 }),
    genTime
  });
  const content = tst.toSchema().toBER(false);
  const signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new pkijs.Attribute({ type: "1.2.840.113549.1.9.3", values: [new asn1js.ObjectIdentifier({ value: OID_TST_INFO })] }),
      new pkijs.Attribute({ type: "1.2.840.113549.1.9.4", values: [new asn1js.OctetString({ valueHex: await crypto.subtle.digest("SHA-256", content) })] })
    ]
  });
  const tbs = new Uint8Array(signedAttrs.toSchema().toBER(false));
  tbs[0] = 0x31;
  const leaf = pkijs.Certificate.fromBER(tsa.cert.rawData);
  const signed = new pkijs.SignedData({
    version: 3,
    digestAlgorithms: [new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 })],
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: OID_TST_INFO, eContent: new asn1js.OctetString({ valueHex: content }) }),
    certificates: [leaf, pkijs.Certificate.fromBER(ca.cert.rawData)],
    signerInfos: [new pkijs.SignerInfo({
      version: 1,
      sid: new pkijs.IssuerAndSerialNumber({ issuer: leaf.issuer, serialNumber: leaf.serialNumber }),
      digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 }),
      signedAttrs,
      signatureAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.11" }),
      signature: new asn1js.OctetString({ valueHex: await crypto.subtle.sign("RSASSA-PKCS1-v1_5", tsa.keys.privateKey, ab(tbs)) })
    })]
  });
  return b64(new pkijs.ContentInfo({ contentType: "1.2.840.113549.1.7.2", content: signed.toSchema(true) }).toSchema().toBER(false));
}
const signatureOf = (cms: string) => new Uint8Array(new pkijs.SignedData({ schema: pkijs.ContentInfo.fromBER(Buffer.from(cms, "base64")).content }).signerInfos[0]!.signature.valueBlock.valueHexView);

async function setup() {
  const icp = await root("CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR");
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(CNPJ))) }) })])));
  const company = await issue(icp, `CN=ACME LTDA:${CNPJ}, O=ICP-Brasil, C=BR`, "02", [san]);
  const anchors = [b64(icp.cert.rawData)];
  const input: MandateInput = {
    credential_id: "cred-stamp-1", agent: { kind: "evm", id: AGENT.address }, principal: { kind: "company", cnpj: CNPJ },
    mandate: { actions: ["pay"], max_per_operation: { amount: 100, currency: "BRL" }, max_per_day: { amount: 500, currency: "BRL" }, currencies: ["BRL"], counterparties: [], payment_instruments: [], valid_from: "2026-11-01T00:00:00Z", valid_until: "2027-03-01T00:00:00Z", delegation: null },
    ttl_seconds: 30 * 86400, now: SIGNED
  };
  const built = await buildMandate(input);
  const { text } = await mandateSigningInput(built);
  const signer = ecnpjSigner({ certificates: [new Uint8Array(company.cert.rawData), new Uint8Array(icp.cert.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", company.keys.privateKey, ab(d))) });
  const issued = await assembleCredential(built, await signer.sign(text), [], { anchors, now: SIGNED });
  const other = await assembleCredential(await buildMandate({ ...input, credential_id: "cred-stamp-2" }), await signer.sign((await mandateSigningInput(await buildMandate({ ...input, credential_id: "cred-stamp-2" }))).text), [], { anchors, now: SIGNED });
  const tsaRoot = await root("CN=AC Raiz de Tempo Teste, O=ICP-Brasil, C=BR");
  const tsa = await authority(tsaRoot, "10");
  const tsaAnchors = [b64(tsaRoot.cert.rawData)];
  const token = await stamp(tsa, tsaRoot, signatureOf(issued.proof.cms), SIGNED);
  return { anchors, issued, other, tsaRoot, tsa, tsaAnchors, token };
}
let cache: ReturnType<typeof setup> | null = null;
const k = () => (cache ??= setup());
const failing = (r: { checks: { rule: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.rule);

describe("time-stamp request", () => {
  it("asks for the SHA-256 of the mandate's signature value, with the authority's certificate", async () => {
    const { issued } = await k();
    const { der, imprint_sha256 } = await timestampRequest(issued.proof.cms);
    const req = pkijs.TimeStampReq.fromBER(ab(der));
    expect(req.certReq).toBe(true);
    expect(req.messageImprint.hashAlgorithm.algorithmId).toBe(OID_SHA256);
    expect(Buffer.from(req.messageImprint.hashedMessage.valueBlock.valueHexView).toString("hex")).toBe(imprint_sha256);
    expect(imprint_sha256).toBe(Buffer.from(await crypto.subtle.digest("SHA-256", ab(signatureOf(issued.proof.cms)))).toString("hex"));
  });
});

describe("time-stamp accepted", () => {
  it("verifies, and says when the signature already existed and who attests it", async () => {
    const { issued, token, tsaAnchors } = await k();
    const p = await verifyTimestamp({ token, cms: issued.proof.cms, anchors: tsaAnchors, now: NOW });
    expect(p.attested_at).toBe(SIGNED.toISOString());
    expect(p.authority_subject).toContain("ACT Teste");
    expect(p.policy).toBe("2.16.76.1.6.6");
    expect(p.revocation.serial_number).toBeTruthy();
  });

  it("addTimestamp puts the token in the proof, and the header carries it", async () => {
    const { issued, token, tsaAnchors } = await k();
    const stamped = await addTimestamp(issued, token, { anchors: tsaAnchors, now: NOW });
    expect(stamped.proof.timestamp).toBe(token);
    expect(stamped.credential).toEqual(issued.credential);
    expect(stamped.timestamp.attested_at).toBe(SIGNED.toISOString());
    expect(decodePrincipalProofHeader(encodePrincipalProofHeader(stamped.proof))).toEqual(stamped.proof);
    expect(() => decodePrincipalProofHeader(Buffer.from(JSON.stringify({ text: "t", cms: "c", timestamp: 1 })).toString("base64url"))).toThrow(/timestamp/);
  });

  it("a verifier that requires a time-stamp accepts the credential and gets the attested time", async () => {
    const { issued, token, anchors, tsaAnchors } = await k();
    const r = await verifySelfIssuedCredential({ credential: issued.credential, proof: { ...issued.proof, timestamp: token }, anchors, now: NOW, timestamp: { anchors: tsaAnchors, required: true } });
    expect(r.ok).toBe(true);
    expect(r.checks.map((c) => c.rule)).toContain("timestamp");
    expect(r.timestamp?.attested_at).toBe(SIGNED.toISOString());
  });

  it("reads a token carried inside the CMS as the signature-time-stamp attribute", async () => {
    const { issued, token, tsaAnchors } = await k();
    const ci = pkijs.ContentInfo.fromBER(Buffer.from(issued.proof.cms, "base64"));
    const signed = new pkijs.SignedData({ schema: ci.content });
    signed.signerInfos[0]!.unsignedAttrs = new pkijs.SignedAndUnsignedAttributes({ type: 1, attributes: [new pkijs.Attribute({ type: OID_SIGNATURE_TIMESTAMP, values: [asn1js.fromBER(Buffer.from(token, "base64")).result] })] });
    const cms = b64(new pkijs.ContentInfo({ contentType: ci.contentType, content: signed.toSchema(true) }).toSchema().toBER(false));
    expect(embeddedTimestamp(issued.proof.cms)).toBeNull();
    expect(embeddedTimestamp(cms)).toBe(token);
    const r = await checkTimestamp({ cms, policy: { anchors: tsaAnchors, required: true }, now: NOW });
    expect(r.ok).toBe(true);
    expect(r.proof?.attested_at).toBe(SIGNED.toISOString());
  });
});

describe("time-stamp policy is the verifier's", () => {
  it("with no policy nothing changes: no rule, no field", async () => {
    const { issued, token, anchors } = await k();
    const r = await verifySelfIssuedCredential({ credential: issued.credential, proof: { ...issued.proof, timestamp: token }, anchors, now: NOW });
    expect(r.ok).toBe(true);
    expect(r.checks.map((c) => c.rule)).not.toContain("timestamp");
    expect("timestamp" in r).toBe(false);
  });

  it("required and absent: refused by that rule alone; not required and absent: accepted, with no attested time", async () => {
    const { issued, anchors, tsaAnchors } = await k();
    const must = await verifySelfIssuedCredential({ ...issued, anchors, now: NOW, timestamp: { anchors: tsaAnchors, required: true } });
    expect(must.ok).toBe(false);
    expect(failing(must)).toEqual(["timestamp"]);
    expect(must.timestamp).toBeNull();
    const may = await verifySelfIssuedCredential({ ...issued, anchors, now: NOW, timestamp: { anchors: tsaAnchors, required: false } });
    expect(may.ok).toBe(true);
    expect(may.timestamp).toBeNull();
  });

  it("an invalid token is refused even when none is required", async () => {
    const { issued, other, tsa, tsaRoot, anchors, tsaAnchors } = await k();
    const foreign = await stamp(tsa, tsaRoot, signatureOf(other.proof.cms), SIGNED);
    const r = await verifySelfIssuedCredential({ credential: issued.credential, proof: { ...issued.proof, timestamp: foreign }, anchors, now: NOW, timestamp: { anchors: tsaAnchors, required: false } });
    expect(r.ok).toBe(false);
    expect(failing(r)).toEqual(["timestamp"]);
  });

  it("has no default: anchors and required must both be given", async () => {
    const { issued, tsaAnchors } = await k();
    for (const policy of [{ anchors: tsaAnchors }, { required: true }, { anchors: [], required: true }, null]) {
      await expect(checkTimestamp({ cms: issued.proof.cms, policy: policy as never, now: NOW })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    }
  });
});

describe("time-stamp refused", () => {
  const refused = async (token: string, why: RegExp = /./, anchorsOverride?: string[]) => {
    const { issued, tsaAnchors } = await k();
    const attempt = verifyTimestamp({ token, cms: issued.proof.cms, anchors: anchorsOverride ?? tsaAnchors, now: NOW });
    await expect(attempt).rejects.toMatchObject({ code: "TIMESTAMP_INVALID" });
    await expect(attempt).rejects.toThrow(why);
  };

  it("a token over another signature", async () => {
    const { other, tsa, tsaRoot } = await k();
    await refused(await stamp(tsa, tsaRoot, signatureOf(other.proof.cms), SIGNED), /another signature/);
  });

  it("an authority outside the verifier's anchors, or no anchors", async () => {
    const { issued, token, anchors } = await k();
    const rogueRoot = await root("CN=Raiz Falsa, O=Outra, C=BR");
    const rogue = await stamp(await authority(rogueRoot, "11"), rogueRoot, signatureOf(issued.proof.cms), SIGNED);
    await refused(rogue);
    await refused(token, /not trusted/, anchors); // the ICP-Brasil root of the mandate is not a time-stamping anchor here
    await refused(token, /no time-stamping trust anchors/, []);
  });

  it("a signer that is not a time-stamping certificate: no usage, not critical, or one usage more", async () => {
    const { issued, tsaRoot } = await k();
    const sig = signatureOf(issued.proof.cms);
    for (const [serial, usages, critical] of [["12", [], true], ["13", [OID_KP_TIMESTAMPING], false], ["14", [OID_KP_TIMESTAMPING, "1.3.6.1.5.5.7.3.4"], true]] as const) {
      await refused(await stamp(await authority(tsaRoot, serial, [...usages], critical), tsaRoot, sig, SIGNED), /time-stamping certificate/);
    }
  });

  it("a time after the verifier's clock, or outside the authority's certificate", async () => {
    const { issued, tsa, tsaRoot } = await k();
    const sig = signatureOf(issued.proof.cms);
    await refused(await stamp(tsa, tsaRoot, sig, new Date("2026-11-11T00:00:00Z")), /after now/);
    const late = await authority(tsaRoot, "15", [OID_KP_TIMESTAMPING], true, { from: new Date("2026-11-05T00:00:00Z") });
    await refused(await stamp(late, tsaRoot, sig, SIGNED), /not valid at the token's time/);
  });

  it("a token altered after it was signed, the mandate's own CMS, and bytes that are no token", async () => {
    const { issued, token } = await k();
    const bytes = Buffer.from(token, "base64");
    const at = bytes.indexOf(Buffer.from("20261104120000Z")); // the genTime inside the signed TSTInfo
    expect(at).toBeGreaterThan(0);
    bytes[at + 3] = 0x35; // 2026 -> 2025: an earlier time than the authority attested
    await refused(bytes.toString("base64"));
    await refused(issued.proof.cms, /no TSTInfo/);
    await refused(Buffer.from("not a token").toString("base64"));
  });
});

describe("why it matters: the time the signer declares against the time an authority attests", () => {
  it("a revocation that would be kept on the declared time is enforced on the attested one", async () => {
    // Key stolen; certificate revoked on 6 Nov. The thief signs on 8 Nov and assembles the credential with its
    // clock set to 4 Nov. The authority, asked on 8 Nov, attests 8 Nov.
    const policy = { by_reason: { keyCompromise: "keep" as const }, other: "revoke" as const };
    const entry = { revoked: true, revoked_at: "2026-11-06T00:00:00Z", reason: "keyCompromise" };
    const { issued, tsa, tsaRoot, tsaAnchors } = await k();
    const declared = issued.credential.authorized_by.signed_at;
    const attested = (await verifyTimestamp({ token: await stamp(tsa, tsaRoot, signatureOf(issued.proof.cms), new Date("2026-11-08T12:00:00Z")), cms: issued.proof.cms, anchors: tsaAnchors, now: NOW })).attested_at;
    expect(revocationEffect(entry, declared, policy)).toBe("none");
    expect(revocationEffect(entry, attested, policy)).toBe("revoke");
  });
});

/**
 * Vectors generated by Alloy from the run commands of docs/formal/timestamp.als (docs/vectors/timestamp-v1.json):
 * the revocation compared with the time the credential declares and with the time a token attests.
 */
interface StampVector { command: string; solution: number; declared: number; attested: number | null; revoked_at: number | null; expected: { on_declared: string; on_attested: string }; note?: string }
const stampFile = JSON.parse(readFileSync(new URL("../../../docs/vectors/timestamp-v1.json", import.meta.url), "utf8")) as { epoch: string; vectors: StampVector[] };

describe("vectors from timestamp.als: declared time against attested time", () => {
  const at = (s: number | null) => (s === null ? null : new Date(Date.parse(stampFile.epoch) + s * 1000).toISOString());
  const keep = { by_reason: { keyCompromise: "keep" as const }, other: "revoke" as const };

  it("has vectors of every command", () => {
    const commands = new Set(stampFile.vectors.map((v) => v.command));
    for (const c of ["StampNeverRevoked", "StampBeforeRevocation", "StampAtRevocation", "BackdatedAfterRevocation", "NoStampDeclaredBefore", "ThiefInsideWindow"]) expect(commands.has(c), c).toBe(true);
  });

  for (const v of stampFile.vectors) {
    it(`${v.command} #${v.solution}: declared ${v.expected.on_declared}, attested ${v.expected.on_attested}${v.note ? ` (${v.note})` : ""}`, () => {
      const entry = { revoked: v.revoked_at !== null, revoked_at: at(v.revoked_at), reason: "keyCompromise" };
      expect(revocationEffect(entry, at(v.declared), keep)).toBe(v.expected.on_declared);
      expect(revocationEffect(entry, at(v.attested), keep)).toBe(v.expected.on_attested);
    });
  }
});
