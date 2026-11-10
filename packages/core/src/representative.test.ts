/// <reference types="node" /> // test-only: Buffer
/**
 * Company mandate signed by a legal representative's e-CPF alone (SPEC section 22, D-43): the form left to a
 * company once it has no signature certificate (Resolução CG ICP-Brasil 211/2024, from 3 March 2029). Accepted only
 * against the verifier's list of representatives; refused without it. Throwaway test chain, never real certificates.
 */
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { privateKeyToAccount } from "viem/accounts";
import { ecnpjSigner } from "./ecnpj-sign.js";
import { OID_ICP_CNPJ, OID_ICP_PERSON, OID_ICP_RESPONSIBLE } from "./icp-brasil.js";
import { type MandateInput, REPRESENTATIVE_LINE, assembleCredential, buildMandate, mandateSigningInput, verifySelfIssuedCredential } from "./issuance.js";
import { addCosignature, verifyCompanyWill } from "./cosign.js";
import { REPRESENTATIVE_METHOD } from "./types.js";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const CNPJ = "11222333000181";
const REP = "52998224725";
const OTHER = "11144477735";
const NOW = new Date("2026-11-04T12:00:00Z");
const AGENT = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

type Pair = { keys: CryptoKeyPair; cert: x509.X509Certificate };
async function ca(name: string): Promise<Pair> {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name, notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  return { keys, cert };
}
async function leaf(root: Pair, who: { cnpj?: string; cpf?: string; responsible?: string }, serial: string, notAfter = new Date("2027-06-01")): Promise<Pair> {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const on = (typeId: string, v: string) => new OtherName({ typeId, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(v))) });
  const others = who.cpf
    ? [on(OID_ICP_PERSON, `01011990${who.cpf}00000000000000000000000000000`)]
    : [on(OID_ICP_CNPJ, who.cnpj!), ...(who.responsible ? [on(OID_ICP_RESPONSIBLE, `01011980${who.responsible}00000000000000000000000000000`)] : [])];
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames(others.map((o) => new GeneralName({ otherName: o })))));
  const subject = who.cpf ? `CN=FULANO DE TAL:${who.cpf}, O=ICP-Brasil, C=BR` : `CN=ACME LTDA:${who.cnpj}, O=ICP-Brasil, C=BR`;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: serial, subject, issuer: root.cert.subject, notBefore: new Date("2026-01-01"), notAfter, signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: root.keys.privateKey, extensions: [san] });
  return { keys, cert };
}
const signerOf = (l: Pair, root: Pair) =>
  ecnpjSigner({ certificates: [new Uint8Array(l.cert.rawData), new Uint8Array(root.cert.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", l.keys.privateKey, d.slice().buffer as ArrayBuffer)) });

const terms = { actions: ["pay"], max_per_operation: { amount: 100, currency: "BRL" }, max_per_day: { amount: 500, currency: "BRL" }, currencies: ["BRL"], counterparties: [], payment_instruments: [], valid_from: "2026-11-01T00:00:00Z", valid_until: "2027-03-01T00:00:00Z", delegation: null };
const input = (signed_by?: "e-cnpj" | "representative"): MandateInput => ({
  credential_id: "cred-rep-1",
  agent: { kind: "evm", id: AGENT.address },
  principal: { kind: "company", cnpj: CNPJ, ...(signed_by ? { signed_by } : {}) },
  mandate: terms,
  ttl_seconds: 7 * 86400,
  now: NOW
});

async function setup() {
  const root = await ca("CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR");
  const company = await leaf(root, { cnpj: CNPJ }, "02");
  const rep = await leaf(root, { cpf: REP }, "03");
  const other = await leaf(root, { cpf: OTHER }, "04");
  const anchors = [b64(root.cert.rawData)];
  const built = await buildMandate(input("representative"));
  const { text } = await mandateSigningInput(built);
  const issued = await assembleCredential(built, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
  return { root, company, rep, other, anchors, built, text, issued };
}
let cache: ReturnType<typeof setup> | null = null;
const k = () => (cache ??= setup());
const reps = () => ["529.982.247-25"]; // formatted on purpose
const failing = (r: { checks: { rule: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.rule);

describe("company mandate signed by a legal representative (section 22)", () => {
  it("issues: the text states the capacity, the credential records the method and nothing personal", async () => {
    const { text, issued } = await k();
    expect(text.split("\n").at(-1)).toBe(REPRESENTATIVE_LINE);
    expect(text).toContain(`cnpj: ${CNPJ}`);
    const c = issued.credential;
    expect(c.authorized_by.method).toBe(REPRESENTATIVE_METHOD);
    expect(c.authorized_by.certificate_subject).toBeUndefined();
    expect((c.principal as { cnpj: string }).cnpj).toBe(CNPJ);
    expect(JSON.stringify(c)).not.toContain(REP);
    expect(JSON.stringify(c)).not.toContain("FULANO");
  });

  it("is refused with no list of representatives: the e-CPF alone never binds a company", async () => {
    const { issued, anchors } = await k();
    const r = await verifySelfIssuedCredential({ ...issued, anchors, now: NOW });
    expect(r.ok).toBe(false);
    expect(failing(r)).toEqual(["representative"]);
  });

  it("is accepted when the verifier's list names the signer", async () => {
    const { issued, anchors } = await k();
    const r = await verifySelfIssuedCredential({ ...issued, anchors, now: NOW, representatives: reps });
    expect(r.ok).toBe(true);
    expect(r.revocation?.serial_number).toBeTruthy();
    expect(JSON.stringify(r)).not.toContain(REP);
  });

  it("is refused when the list does not name the signer, is empty, or fails", async () => {
    const { issued, anchors } = await k();
    for (const representatives of [() => [OTHER], () => [], async () => { throw new Error("registry down"); }]) {
      const r = await verifySelfIssuedCredential({ ...issued, anchors, now: NOW, representatives });
      expect(r.ok).toBe(false);
      expect(failing(r)).toEqual(["representative"]);
    }
  });

  it("the issuer may check its own list at assembly, and is refused there", async () => {
    const { built, text, rep, root, anchors } = await k();
    const cms = await signerOf(rep, root).sign(text);
    await expect(assembleCredential(built, cms, [], { anchors, now: NOW, representatives: () => [OTHER] })).rejects.toThrow(/representative/);
    await expect(assembleCredential(built, cms, [], { anchors, now: NOW, representatives: reps })).resolves.toBeTruthy();
  });

  it("an e-CNPJ cannot sign the representative's text, nor an e-CPF the e-CNPJ's", async () => {
    const { built, text, company, rep, root, anchors } = await k();
    await expect(assembleCredential(built, await signerOf(company, root).sign(text), [], { anchors, now: NOW })).rejects.toThrow(/company certificate/);
    const byCnpj = await buildMandate(input());
    const plain = (await mandateSigningInput(byCnpj)).text;
    expect(plain).not.toContain("signed-by");
    await expect(assembleCredential(byCnpj, await signerOf(rep, root).sign(plain), [], { anchors, now: NOW })).rejects.toThrow(/natural person/);
  });

  it("the method cannot be swapped after signing, in either direction", async () => {
    const { issued, company, root, anchors } = await k();
    const asCnpj = { ...issued, credential: { ...issued.credential, authorized_by: { ...issued.credential.authorized_by, method: "icp-brasil-e-cnpj" as const } } };
    expect((await verifySelfIssuedCredential({ ...asCnpj, anchors, now: NOW, representatives: reps })).ok).toBe(false);
    const byCnpj = await buildMandate(input());
    const real = await assembleCredential(byCnpj, await signerOf(company, root).sign((await mandateSigningInput(byCnpj)).text), [], { anchors, now: NOW });
    const asRep = { ...real, credential: { ...real.credential, authorized_by: { ...real.credential.authorized_by, method: REPRESENTATIVE_METHOD } } };
    expect((await verifySelfIssuedCredential({ ...asRep, anchors, now: NOW, representatives: reps })).ok).toBe(false);
  });

  it("verifyCompanyWill counts the signer as the first representative, and only from the list", async () => {
    const { issued, anchors, other, root } = await k();
    const one = await verifyCompanyWill(issued, { anchors, now: NOW, representatives: reps });
    expect(one).toMatchObject({ ok: true, representatives_counted: 1 });
    const noList = await verifyCompanyWill(issued, { anchors, now: NOW, acceptCertificateResponsible: true });
    expect(noList).toMatchObject({ ok: false, code: "COMPANY_SIGNATURE_INVALID" });
    const both = () => [REP, OTHER];
    expect(await verifyCompanyWill(issued, { anchors, now: NOW, representatives: both, minCosigners: 2 })).toMatchObject({ ok: false, code: "INSUFFICIENT_COSIGNERS", representatives_counted: 1 });
    const two = await addCosignature(issued, await signerOf(other, root).sign(issued.proof.text), [], { anchors, now: NOW });
    expect(await verifyCompanyWill(two, { anchors, now: NOW, representatives: both, minCosigners: 2 })).toMatchObject({ ok: true, representatives_counted: 2 });
    expect(JSON.stringify(two.credential)).not.toContain(OTHER);
  });

  it("the same person signing and co-signing counts once", async () => {
    const { issued, anchors, rep, root } = await k();
    const twice = await addCosignature(issued, await signerOf(rep, root).sign(issued.proof.text), [], { anchors, now: NOW });
    expect(await verifyCompanyWill(twice, { anchors, now: NOW, representatives: reps, minCosigners: 2 })).toMatchObject({ ok: false, code: "INSUFFICIENT_COSIGNERS", representatives_counted: 1 });
  });

  it("buildMandate refuses an unknown signer", async () => {
    await expect(buildMandate({ ...input(), principal: { kind: "company", cnpj: CNPJ, signed_by: "seal" as never } })).rejects.toThrow(/signed_by/);
  });
});
