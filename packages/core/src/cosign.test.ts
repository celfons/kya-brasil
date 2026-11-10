/// <reference types="node" /> // test-only: Buffer
/**
 * Co-signature by a legal representative (SPEC section 21): accepted, CPF not a representative, tampered text,
 * missing, untrusted / expired e-CPF, quorum. Throwaway ICP-Brasil test chain, never real certificates.
 */
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { privateKeyToAccount } from "viem/accounts";
import { ecnpjSigner } from "./ecnpj-sign.js";
import { OID_ICP_CNPJ, OID_ICP_PERSON, OID_ICP_RESPONSIBLE, responsibleCpfFromCertificate } from "./icp-brasil.js";
import { type MandateInput, REPRESENTATIVE_LINE, assembleCredential, buildMandate, mandateSigningInput, verifySelfIssuedCredential } from "./issuance.js";
import { REPRESENTATIVE_METHOD } from "./types.js";
import { addCosignature, verifyCompanyWill } from "./cosign.js";
import { decodePrincipalProofHeader, encodePrincipalProofHeader } from "./principal-proof.js";

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

const input: MandateInput = {
  credential_id: "cred-cosign-1",
  agent: { kind: "evm", id: AGENT.address },
  principal: { kind: "company", cnpj: CNPJ },
  mandate: { actions: ["pay"], max_per_operation: { amount: 100, currency: "BRL" }, max_per_day: { amount: 500, currency: "BRL" }, currencies: ["BRL"], counterparties: [], payment_instruments: [], valid_from: "2026-11-01T00:00:00Z", valid_until: "2027-03-01T00:00:00Z", delegation: null },
  ttl_seconds: 7 * 86400,
  now: NOW
};

async function setup() {
  const root = await ca("CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR");
  const rogueRoot = await ca("CN=AC Falsa, O=Outra, C=BR");
  const company = await leaf(root, { cnpj: CNPJ }, "02");
  const rep = await leaf(root, { cpf: REP }, "03");
  const other = await leaf(root, { cpf: OTHER }, "04");
  const rogue = await leaf(rogueRoot, { cpf: REP }, "05");
  const expired = await leaf(root, { cpf: REP }, "06", new Date("2026-06-01"));
  const anchors = [b64(root.cert.rawData)];
  const built = await buildMandate(input);
  const { text } = await mandateSigningInput(built);
  const issued = await assembleCredential(built, await signerOf(company, root).sign(text), [], { anchors, now: NOW });
  return { root, rogueRoot, company, rep, other, rogue, expired, anchors, text, issued };
}
let cache: ReturnType<typeof setup> | null = null;
const k = () => (cache ??= setup());
const reps = () => ["529.982.247-25"]; // formatted on purpose

describe("co-signature by a legal representative (section 21)", () => {
  it("accepted: e-CPF of a representative over the same text; the credential carries no CPF", async () => {
    const { root, rep, anchors, text, issued } = await k();
    const cs = await addCosignature(issued, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
    expect(cs.credential.cosignatures).toHaveLength(1);
    expect(JSON.stringify(cs.credential)).not.toContain(REP);
    expect(JSON.stringify(cs.credential)).not.toContain("FULANO");
    expect((await verifySelfIssuedCredential({ ...cs, anchors, now: NOW })).ok).toBe(true);
    let asked = "";
    const r = await verifyCompanyWill(cs, { anchors, now: NOW, representatives: async (c) => ((asked = c), reps()) });
    expect(asked).toBe(CNPJ);
    expect(r).toMatchObject({ ok: true, representatives_counted: 1 });
    expect(JSON.stringify(r)).not.toContain(REP);
    expect(r.cosigners[0]!.revocation?.serial_number).toBe("3");
    const proof = decodePrincipalProofHeader(encodePrincipalProofHeader(cs.proof));
    expect((await verifyCompanyWill({ credential: cs.credential, proof }, { anchors, now: NOW, representatives: reps })).ok).toBe(true);
    expect(await verifyCompanyWill(cs, { anchors, now: NOW, representatives: reps, minCosigners: 2 })).toMatchObject({ ok: false, code: "INSUFFICIENT_COSIGNERS" });
  });

  it("refused: the co-signer's CPF is not a representative", async () => {
    const { root, rep, other, anchors, text, issued } = await k();
    const cs = await addCosignature(issued, await signerOf(other, root).sign(text), [], { anchors, now: NOW });
    expect(await verifyCompanyWill(cs, { anchors, now: NOW, representatives: reps })).toMatchObject({ ok: false, code: "COSIGNER_NOT_REPRESENTATIVE" });
    const both = await addCosignature(cs, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
    expect((await verifyCompanyWill(both, { anchors, now: NOW, representatives: reps })).ok).toBe(true);
    expect((await verifyCompanyWill(both, { anchors, now: NOW, representatives: () => [REP, OTHER], minCosigners: 2 })).ok).toBe(true);
  });

  it("refused: a co-signature over a different text", async () => {
    const { root, rep, anchors, text, issued } = await k();
    const other = text.replace("cred-cosign-1", "cred-cosign-2");
    await expect(addCosignature(issued, await signerOf(rep, root).sign(other), [], { anchors, now: NOW })).rejects.toMatchObject({ code: "CHALLENGE_FAILED" });
    const good = await addCosignature(issued, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
    const tampered = { credential: good.credential, proof: { ...good.proof, cosignatures: [await signerOf(rep, root).sign(other)] } };
    expect(await verifyCompanyWill(tampered, { anchors, now: NOW, representatives: reps })).toMatchObject({ ok: false, code: "COSIGNATURE_TEXT_MISMATCH" });
    expect(await verifyCompanyWill({ credential: good.credential, proof: issued.proof }, { anchors, now: NOW, representatives: reps })).toMatchObject({ ok: false, code: "COSIGNATURE_NOT_RECORDED" });
  });

  it("refused: no co-signature", async () => {
    const { anchors, issued } = await k();
    expect(await verifyCompanyWill(issued, { anchors, now: NOW, representatives: reps })).toMatchObject({ ok: false, code: "NO_COSIGNATURE" });
  });

  it("refused: e-CPF untrusted or expired, e-CNPJ as co-signer, duplicate, broken company signature", async () => {
    const { root, rogueRoot, rep, rogue, expired, company, anchors, text, issued } = await k();
    await expect(addCosignature(issued, await signerOf(rogue, rogueRoot).sign(text), [], { anchors, now: NOW })).rejects.toMatchObject({ code: "CERTIFICATE_INVALID" });
    await expect(addCosignature(issued, await signerOf(expired, root).sign(text), [], { anchors, now: NOW })).rejects.toMatchObject({ code: "CERTIFICATE_INVALID" });
    await expect(addCosignature(issued, await signerOf(company, root).sign(text), [], { anchors, now: NOW })).rejects.toMatchObject({ code: "CERTIFICATE_INVALID" });
    const cs = await addCosignature(issued, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
    await expect(addCosignature(cs, await signerOf(rep, root).sign(text), [], { anchors, now: NOW })).rejects.toMatchObject({ code: "CONFLICT" });
    const smuggled = { credential: cs.credential, proof: { ...cs.proof, cosignatures: [await signerOf(rogue, rogueRoot).sign(text)] } };
    expect(await verifyCompanyWill(smuggled, { anchors, now: NOW, representatives: reps })).toMatchObject({ ok: false, code: "COSIGNER_CERTIFICATE_INVALID" });
    expect(await verifyCompanyWill({ ...cs, credential: { ...cs.credential, credential_id: "x" } }, { anchors, now: NOW, representatives: reps })).toMatchObject({ ok: false, code: "COMPANY_SIGNATURE_INVALID" });
  });
});

describe("co-signature by the person responsible named in the e-CNPJ (no list)", () => {
  async function withResponsible() {
    const base = await k();
    const company = await leaf(base.root, { cnpj: CNPJ, responsible: REP }, "07");
    const issued = await assembleCredential(await buildMandate(input), await signerOf(company, base.root).sign(base.text), [], { anchors: base.anchors, now: NOW });
    return { ...base, company, issued };
  }

  it("reads the responsible's CPF from the e-CNPJ only", async () => {
    const { company, rep } = await withResponsible();
    expect(responsibleCpfFromCertificate(new x509.X509Certificate(company.cert.rawData))).toBe(REP);
    expect(responsibleCpfFromCertificate(new x509.X509Certificate(rep.cert.rawData))).toBeNull();
    const { company: plain } = await k();
    expect(responsibleCpfFromCertificate(new x509.X509Certificate(plain.cert.rawData))).toBeNull();
  });

  it("accepted: the co-signer is the responsible named in the e-CNPJ, with no list; the result carries no CPF", async () => {
    const { root, rep, anchors, text, issued } = await withResponsible();
    const cs = await addCosignature(issued, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
    const r = await verifyCompanyWill(cs, { anchors, now: NOW, acceptCertificateResponsible: true });
    expect(r).toMatchObject({ ok: true, representatives_counted: 1 });
    expect(r.cosigners[0]!.basis).toBe("ecnpj_responsible");
    expect(JSON.stringify(r)).not.toContain(REP);
    expect(await verifyCompanyWill(cs, { anchors, now: NOW, representatives: () => [] })).toMatchObject({ ok: false, code: "COSIGNER_NOT_REPRESENTATIVE" });
  });

  it("refused: another person co-signs, or the e-CNPJ names no responsible", async () => {
    const { root, other, anchors, text, issued } = await withResponsible();
    const cs = await addCosignature(issued, await signerOf(other, root).sign(text), [], { anchors, now: NOW });
    expect(await verifyCompanyWill(cs, { anchors, now: NOW, acceptCertificateResponsible: true })).toMatchObject({ ok: false, code: "COSIGNER_NOT_REPRESENTATIVE" });
    const plain = await k();
    const cs2 = await addCosignature(plain.issued, await signerOf(plain.rep, plain.root).sign(plain.text), [], { anchors: plain.anchors, now: NOW });
    expect(await verifyCompanyWill(cs2, { anchors: plain.anchors, now: NOW, acceptCertificateResponsible: true })).toMatchObject({ ok: false, code: "COSIGNER_NOT_REPRESENTATIVE" });
  });

  it("both sources count together, and one source is required", async () => {
    const { root, rep, other, anchors, text, issued } = await withResponsible();
    const one = await addCosignature(issued, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
    const two = await addCosignature(one, await signerOf(other, root).sign(text), [], { anchors, now: NOW });
    const r = await verifyCompanyWill(two, { anchors, now: NOW, acceptCertificateResponsible: true, representatives: () => [OTHER], minCosigners: 2 });
    expect(r).toMatchObject({ ok: true, representatives_counted: 2 });
    expect(r.cosigners.map((c) => c.basis).sort()).toEqual(["ecnpj_responsible", "representatives"]);
    await expect(verifyCompanyWill(two, { anchors, now: NOW })).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });
});

/**
 * Company mandate signed by a legal representative's e-CPF alone (SPEC section 22, D-43): the form left to a
 * company once it has no signature certificate (Resolução CG ICP-Brasil 211/2024). Accepted only against the
 * verifier's list of representatives; refused without it.
 */
const terms = { actions: ["pay"], max_per_operation: { amount: 100, currency: "BRL" }, max_per_day: { amount: 500, currency: "BRL" }, currencies: ["BRL"], counterparties: [], payment_instruments: [], valid_from: "2026-11-01T00:00:00Z", valid_until: "2027-03-01T00:00:00Z", delegation: null };
const repInput = (signed_by?: "e-cnpj" | "representative"): MandateInput => ({
  credential_id: "cred-rep-1",
  agent: { kind: "evm", id: AGENT.address },
  principal: { kind: "company", cnpj: CNPJ, ...(signed_by ? { signed_by } : {}) },
  mandate: terms,
  ttl_seconds: 7 * 86400,
  now: NOW
});

async function repSetup() {
  const root = await ca("CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR");
  const company = await leaf(root, { cnpj: CNPJ }, "02");
  const rep = await leaf(root, { cpf: REP }, "03");
  const other = await leaf(root, { cpf: OTHER }, "04");
  const anchors = [b64(root.cert.rawData)];
  const built = await buildMandate(repInput("representative"));
  const { text } = await mandateSigningInput(built);
  const issued = await assembleCredential(built, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
  return { root, company, rep, other, anchors, built, text, issued };
}
let repCache: ReturnType<typeof repSetup> | null = null;
const rk = () => (repCache ??= repSetup());
const failing = (r: { checks: { rule: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.rule);

describe("company mandate signed by a legal representative (section 22)", () => {
  it("issues: the text states the capacity, the credential records the method and nothing personal", async () => {
    const { text, issued } = await rk();
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
    const { issued, anchors } = await rk();
    const r = await verifySelfIssuedCredential({ ...issued, anchors, now: NOW });
    expect(r.ok).toBe(false);
    expect(failing(r)).toEqual(["representative"]);
  });

  it("is accepted when the verifier's list names the signer", async () => {
    const { issued, anchors } = await rk();
    const r = await verifySelfIssuedCredential({ ...issued, anchors, now: NOW, representatives: reps });
    expect(r.ok).toBe(true);
    expect(r.revocation?.serial_number).toBeTruthy();
    expect(JSON.stringify(r)).not.toContain(REP);
  });

  it("is refused when the list does not name the signer, is empty, or fails", async () => {
    const { issued, anchors } = await rk();
    for (const representatives of [() => [OTHER], () => [], async () => { throw new Error("registry down"); }]) {
      const r = await verifySelfIssuedCredential({ ...issued, anchors, now: NOW, representatives });
      expect(r.ok).toBe(false);
      expect(failing(r)).toEqual(["representative"]);
    }
  });

  it("the issuer may check its own list at assembly, and is refused there", async () => {
    const { built, text, rep, root, anchors } = await rk();
    const cms = await signerOf(rep, root).sign(text);
    await expect(assembleCredential(built, cms, [], { anchors, now: NOW, representatives: () => [OTHER] })).rejects.toThrow(/representative/);
    await expect(assembleCredential(built, cms, [], { anchors, now: NOW, representatives: reps })).resolves.toBeTruthy();
  });

  it("an e-CNPJ cannot sign the representative's text, nor an e-CPF the e-CNPJ's", async () => {
    const { built, text, company, rep, root, anchors } = await rk();
    await expect(assembleCredential(built, await signerOf(company, root).sign(text), [], { anchors, now: NOW })).rejects.toThrow(/company certificate/);
    const byCnpj = await buildMandate(repInput());
    const plain = (await mandateSigningInput(byCnpj)).text;
    expect(plain).not.toContain("signed-by");
    await expect(assembleCredential(byCnpj, await signerOf(rep, root).sign(plain), [], { anchors, now: NOW })).rejects.toThrow(/natural person/);
  });

  it("the method cannot be swapped after signing, in either direction", async () => {
    const { issued, company, root, anchors } = await rk();
    const asCnpj = { ...issued, credential: { ...issued.credential, authorized_by: { ...issued.credential.authorized_by, method: "icp-brasil-e-cnpj" as const } } };
    expect((await verifySelfIssuedCredential({ ...asCnpj, anchors, now: NOW, representatives: reps })).ok).toBe(false);
    const byCnpj = await buildMandate(repInput());
    const real = await assembleCredential(byCnpj, await signerOf(company, root).sign((await mandateSigningInput(byCnpj)).text), [], { anchors, now: NOW });
    const asRep = { ...real, credential: { ...real.credential, authorized_by: { ...real.credential.authorized_by, method: REPRESENTATIVE_METHOD } } };
    expect((await verifySelfIssuedCredential({ ...asRep, anchors, now: NOW, representatives: reps })).ok).toBe(false);
  });

  it("verifyCompanyWill counts the signer as the first representative, and only from the list", async () => {
    const { issued, anchors, other, root } = await rk();
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
    const { issued, anchors, rep, root } = await rk();
    const twice = await addCosignature(issued, await signerOf(rep, root).sign(issued.proof.text), [], { anchors, now: NOW });
    expect(await verifyCompanyWill(twice, { anchors, now: NOW, representatives: reps, minCosigners: 2 })).toMatchObject({ ok: false, code: "INSUFFICIENT_COSIGNERS", representatives_counted: 1 });
  });

  it("buildMandate refuses an unknown signer", async () => {
    await expect(buildMandate({ ...repInput(), principal: { kind: "company", cnpj: CNPJ, signed_by: "seal" as never } })).rejects.toThrow(/signed_by/);
  });
});

