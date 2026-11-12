/// <reference types="node" /> // test-only: Buffer, node:fs
/**
 * Co-signature by a legal representative (SPEC section 21): accepted, CPF not a representative, tampered text,
 * missing, untrusted / expired e-CPF, quorum. Throwaway ICP-Brasil test chain, never real certificates.
 */
import "reflect-metadata";
import { readFileSync } from "node:fs";
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
import { type PrincipalProof, decodePrincipalProofHeader, encodePrincipalProofHeader, verifyPrincipalProof } from "./principal-proof.js";
import type { Credential } from "./types.js";

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
async function leaf(root: Pair, who: { cnpj?: string; cpf?: string; responsible?: string }, serial: string, notAfter = new Date("2027-06-01"), policy?: string): Promise<Pair> {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const on = (typeId: string, v: string) => new OtherName({ typeId, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(v))) });
  const others = who.cpf
    ? [on(OID_ICP_PERSON, `01011990${who.cpf}00000000000000000000000000000`)]
    : [on(OID_ICP_CNPJ, who.cnpj!), ...(who.responsible ? [on(OID_ICP_RESPONSIBLE, `01011980${who.responsible}00000000000000000000000000000`)] : [])];
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames(others.map((o) => new GeneralName({ otherName: o })))));
  const subject = who.cpf ? `CN=FULANO DE TAL:${who.cpf}, O=ICP-Brasil, C=BR` : `CN=ACME LTDA:${who.cnpj}, O=ICP-Brasil, C=BR`;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: serial, subject, issuer: root.cert.subject, notBefore: new Date("2026-01-01"), notAfter, signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: root.keys.privateKey, extensions: [san, ...(policy ? [new x509.CertificatePolicyExtension([policy])] : [])] });
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


/**
 * Vectors generated by Alloy from the run commands of docs/formal/representative.als
 * (docs/vectors/representative-v1.json). The two trust assumptions the library cannot see (a stale list, a lent
 * e-CPF) are vectors it must ACCEPT; the test keeps them so that the assumption stays written down.
 */
interface RepVector {
  command: string; solution: number; signer: "e-cpf" | "seal"; has_list: boolean; same_text: boolean; signer_listed?: boolean;
  expected: { ok: boolean; reason?: "not-listed" | "other-text" | "no-list" | "seal"; assumption?: string };
}
const repVectors = (JSON.parse(readFileSync(new URL("../../../docs/vectors/representative-v1.json", import.meta.url), "utf8")) as { vectors: RepVector[] }).vectors;

describe("vectors from representative.als: company mandate signed by one certificate", () => {
  it("has vectors of every command", () => {
    const commands = new Set(repVectors.map((v) => v.command));
    for (const c of ["RepListedSameText", "RepNotListed", "RepOtherText", "RepNoList", "RepSeal", "RepStaleList", "RepLentECpf"]) expect(commands.has(c), c).toBe(true);
  });

  for (const v of repVectors) {
    it(`${v.command} #${v.solution}: ${v.expected.ok ? "accepted" : v.expected.reason}${v.expected.assumption ? ` (assumes ${v.expected.assumption})` : ""}`, async () => {
      const { root, rep, anchors, built, text, issued } = await rk();
      const list = v.has_list ? { representatives: () => (v.signer_listed ? [REP] : [OTHER]) } : {};
      let cms = issued.proof.cms;
      if (v.signer === "seal") {
        const seal = await leaf(root, { cnpj: CNPJ }, "07", undefined, "2.16.76.1.2.201.1");
        cms = await signerOf(seal, root).sign(text);
        await expect(assembleCredential(built, cms, [], { anchors, now: NOW, ...list })).rejects.toThrow(/electronic seal/);
      } else if (!v.same_text) {
        // A signature over another text cannot be assembled, so it is smuggled into the proof.
        cms = await signerOf(rep, root).sign(text.replace("cred-rep-1", "cred-rep-2"));
        await expect(assembleCredential(built, cms, [], { anchors, now: NOW, ...list })).rejects.toBeTruthy();
      }
      const r = await verifySelfIssuedCredential({ credential: issued.credential, proof: { ...issued.proof, cms }, anchors, now: NOW, ...list });
      expect(r.ok).toBe(v.expected.ok);
      if (v.expected.reason === "not-listed" || v.expected.reason === "no-list") expect(failing(r)).toEqual(["representative"]);
      if (v.expected.reason === "other-text" || v.expected.reason === "seal") expect(failing(r)).toContain("signature"); // refused before the list is even consulted
    });
  }
});

// Mutation testing (research/mutation) showed that each check of the principal's proof could be weakened without
// any test failing: the tests above ask whether the whole verification passes, not which check refuses and why.
describe("the principal's proof, one check at a time", () => {
  const SELF = "urn:kya-brasil:self";
  const verify = (credential: Credential, proof: PrincipalProof, anchors: string[], extra: object = {}) => verifyPrincipalProof({ credential, proof, anchors, now: NOW, ...extra });
  const detailOf = (r: { checks: { rule: string; detail: string }[] }, rule: string) => r.checks.find((c) => c.rule === rule)?.detail;

  it("reports every check of an e-CNPJ proof, with what it found", async () => {
    const { issued, anchors } = await k();
    const r = await verify(issued.credential, issued.proof, anchors);
    expect(r.ok).toBe(true);
    expect(r.checks.map((c) => [c.rule, c.ok])).toEqual([["signature", true], ["certificate", true], ["agent", true], ["principal", true], ["issuer", true], ["mandate", true]]);
    expect(detailOf(r, "signature")).toBe("e-CNPJ signature over the text verifies up to the ICP-Brasil anchors");
    expect(detailOf(r, "certificate")).toBe("signed with the certificate the credential records");
    expect(detailOf(r, "agent")).toBe(`text names the credential's agent evm:${AGENT.address}`);
    expect(detailOf(r, "principal")).toBe(`text names CNPJ ${CNPJ}`);
    expect(detailOf(r, "issuer")).toBe(`text names issuer ${SELF}`);
    expect(detailOf(r, "mandate")).toBe("text commits to the credential's mandate");
    expect(r.revocation).toMatchObject({ serial_number: "2", crl_urls: [] });
    expect(r.revocation?.issuer_certificate).toBeTruthy();
    expect(r).not.toHaveProperty("timestamp");
  });

  it("reports the representative's check between the signature and the certificate", async () => {
    const { issued, anchors } = await rk();
    const r = await verify(issued.credential, issued.proof, anchors, { representatives: () => [Number(REP)] });
    expect(r.ok).toBe(true);
    expect(r.checks.map((c) => c.rule)).toEqual(["signature", "representative", "certificate", "agent", "principal", "issuer", "mandate"]);
    expect(detailOf(r, "signature")).toBe("e-CPF signature over the text verifies up to the ICP-Brasil anchors");
    expect(detailOf(r, "representative")).toBe(`the signer is a legal representative of CNPJ ${CNPJ} in the verifier's list`);
    const notListed = await verify(issued.credential, issued.proof, anchors, { representatives: () => [OTHER] });
    expect(failing(notListed)).toEqual(["representative"]);
    expect(detailOf(notListed, "representative")).toBe(`the signer is not a legal representative of CNPJ ${CNPJ} in the verifier's list`);
    const down = await verify(issued.credential, issued.proof, anchors, { representatives: async () => { throw new Error("registry down"); } });
    expect(detailOf(down, "representative")).toBe("the list of representatives is unavailable: registry down");
    for (const notAFunction of [undefined, [REP], REP, {}]) {
      const none = await verify(issued.credential, issued.proof, anchors, { representatives: notAFunction });
      expect(failing(none)).toEqual(["representative"]);
      expect(detailOf(none, "representative")).toBe("a company credential signed by a legal representative needs the verifier's list of representatives (representatives(cnpj)); none was given");
    }
  });

  it("refuses a proof without text and CMS, and a clock that is not a date, before anything else", async () => {
    const { issued, anchors } = await k();
    for (const proof of [null, undefined, {}, { text: issued.proof.text }, { cms: issued.proof.cms }, { text: 5, cms: issued.proof.cms }, { text: issued.proof.text, cms: 5 }]) {
      expect(await verify(issued.credential, proof as never, anchors)).toEqual({ ok: false, checks: [{ rule: "signature", ok: false, detail: "proof must carry the signed text and the CMS" }], revocation: null });
    }
    for (const now of [new Date("x"), "2026-11-04T12:00:00Z", NOW.getTime(), undefined]) {
      expect(await verifyPrincipalProof({ credential: issued.credential, proof: issued.proof, anchors, now: now as never })).toEqual({ ok: false, checks: [{ rule: "signature", ok: false, detail: "the verifier's clock is not a valid date" }], revocation: null });
    }
  });

  it("names the one check that fails when one field of the credential is changed", async () => {
    const { issued, anchors } = await rk();
    const c = issued.credential;
    const list = { representatives: () => [REP] };
    const changed = async (over: Partial<Credential>) => verify({ ...c, ...over } as Credential, issued.proof, anchors, list);

    const agent = await changed({ agent: { kind: "evm", id: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" } });
    expect(failing(agent)).toEqual(["agent"]);
    expect(detailOf(agent, "agent")).toBe(`text names agent evm:${AGENT.address}, the credential evm:0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC`);

    const principal = await changed({ principal: { ...(c.principal as object), cnpj: "33000167000101" } as Credential["principal"] });
    expect(failing(principal)).toEqual(["principal"]);
    expect(detailOf(principal, "principal")).toBe(`text names CNPJ ${CNPJ}, the credential 33000167000101`);

    const issuer = await changed({ issuer: "https://issuer.example" });
    expect(failing(issuer)).toEqual(["issuer"]);
    expect(detailOf(issuer, "issuer")).toBe(`text names issuer ${SELF}, the credential https://issuer.example`);

    const certificate = await changed({ authorized_by: { ...c.authorized_by, certificate_sha256: "00".repeat(32) } });
    expect(failing(certificate)).toEqual(["certificate"]);
    expect(detailOf(certificate, "certificate")).toBe("signed with another certificate than the one the credential records");

    const mandate = await changed({ mandate: { ...c.mandate, max_per_day: { amount: 5000, currency: "BRL" } } });
    expect(failing(mandate)).toEqual(["mandate"]);
    expect(detailOf(mandate, "mandate")).toBe("text commits to another mandate than the credential's");
    // The hash the credential records must be the signed one; a credential that records none is judged by the text.
    expect(failing(await changed({ authorized_by: { ...c.authorized_by, mandate_sha256: "00".repeat(32) } }))).toEqual(["mandate"]);
    expect((await changed({ authorized_by: { ...c.authorized_by, mandate_sha256: undefined } })).ok).toBe(true);
    // A mandate that is not JSON data commits to nothing.
    expect(failing(await changed({ mandate: { ...c.mandate, note: Number.NaN } as Credential["mandate"] }))).toEqual(["mandate"]);
  });

  it("reads each line of the signed text once: a missing or repeated line is not a statement", async () => {
    const { issued, anchors, company, root } = await k();
    const signed = async (text: string) => ({ text, cms: await signerOf(company, root).sign(text) });
    const bare = await verify(issued.credential, await signed(`KYA Brasil: prove this agent key acts for a company\nissuer: ${SELF}`), anchors);
    expect(failing(bare)).toEqual(["agent", "principal", "mandate"]);
    expect(detailOf(bare, "agent")).toBe(`text names agent (none), the credential evm:${AGENT.address}`);
    expect(detailOf(bare, "principal")).toBe(`text names CNPJ (none), the credential ${CNPJ}`);
    expect(detailOf(bare, "mandate")).toBe("text carries no mandate hash (signed before D-33)");
    const noIssuer = await verify(issued.credential, await signed(issued.proof.text.replace(`issuer: ${SELF}\n`, "")), anchors);
    expect(failing(noIssuer)).toEqual(["issuer"]);
    expect(detailOf(noIssuer, "issuer")).toBe(`text names issuer (none), the credential ${SELF}`);
    for (const line of ["agent", "cnpj", "issuer", "mandate-sha256"]) {
      const original = issued.proof.text.split("\n").find((l) => l.startsWith(`${line}: `)) as string;
      const twice = await verify(issued.credential, await signed(`${issued.proof.text}\n${original}`), anchors);
      expect(failing(twice), line).toEqual([line === "cnpj" ? "principal" : line === "mandate-sha256" ? "mandate" : line]);
    }
    // A key that only begins like the line's is another line.
    const other = await verify(issued.credential, await signed(issued.proof.text.replace("agent: ", "agent:")), anchors);
    expect(failing(other)).toEqual(["agent"]);
  });

  it("reports a signature that does not verify, and then has no certificate to compare", async () => {
    const { issued, anchors } = await rk();
    const bad = await verify(issued.credential, { text: issued.proof.text, cms: "AAAA" }, anchors, { representatives: () => [REP] });
    expect(bad.ok).toBe(false);
    expect(bad.revocation).toBeNull();
    expect(bad.checks.map((c) => c.rule)).toEqual(["signature", "representative", "agent", "principal", "issuer", "mandate"]);
    expect(failing(bad)).toEqual(["signature", "representative"]);
    expect(detailOf(bad, "signature")).toMatch(/^signature is not a CMS SignedData: /);
    expect(detailOf(bad, "representative")).toBe("the signer could not be identified");
    const otherText = await verify(issued.credential, { text: `${issued.proof.text} `, cms: issued.proof.cms }, anchors, { representatives: () => [REP] });
    expect(failing(otherText)).toContain("signature");
  });

  it("carries a proof in a header, and refuses a header that is not one", () => {
    const base = { text: "a\nb", cms: "AAAA" };
    for (const proof of [base, { ...base, cosignatures: ["BBBB", "CCCC"] }, { ...base, timestamp: "DDDD" }, { ...base, cosignatures: ["BBBB"], timestamp: "DDDD" }]) {
      expect(decodePrincipalProofHeader(` ${encodePrincipalProofHeader(proof)}\n`)).toEqual(proof);
    }
    // An empty list and an empty token are left out.
    expect(decodePrincipalProofHeader(encodePrincipalProofHeader({ ...base, cosignatures: [], timestamp: "" }))).toEqual(base);
    const header = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    for (const notJson of ["%%%", "", Buffer.from("not json").toString("base64url")]) expect(() => decodePrincipalProofHeader(notJson)).toThrow("KYA-Principal-Proof is not base64url JSON");
    for (const o of [null, 5, {}, { text: "a" }, { cms: "AAAA" }, { text: 5, cms: "AAAA" }, { text: "a", cms: 5 }]) expect(() => decodePrincipalProofHeader(header(o))).toThrow("KYA-Principal-Proof must carry text and cms");
    for (const timestamp of [5, null, ["DDDD"]]) expect(() => decodePrincipalProofHeader(header({ ...base, timestamp }))).toThrow("KYA-Principal-Proof timestamp must be a base64 time-stamp token");
    for (const cosignatures of ["BBBB", 5, null, ["BBBB", 5], [null]]) expect(() => decodePrincipalProofHeader(header({ ...base, cosignatures }))).toThrow("KYA-Principal-Proof cosignatures must be a list of base64 CMS");
  });
});

// Mutation testing (research/mutation) showed that the refusals and the counts of the co-signature could be
// changed without any test failing: the tests above check the code of a refusal, not what it says nor what it counts.
describe("co-signature at the edge of each rule", () => {
  it("requires each input of addCosignature, and says which one is missing", async () => {
    const { root, rep, anchors, text, issued } = await k();
    const cms = await signerOf(rep, root).sign(text);
    const add = (i: unknown, c: unknown = cms, chain: unknown = [], opts: unknown = { anchors, now: NOW }) => addCosignature(i as never, c as never, chain as never, opts as never);
    for (const i of [null, undefined, {}, { credential: issued.credential }, { proof: issued.proof }, { credential: issued.credential, proof: { cms: "AAAA" } }]) await expect(add(i)).rejects.toThrow("issued: { credential, proof } from assembleCredential is required");
    await expect(add({ ...issued, credential: { ...issued.credential, issuer: "https://issuer.example" } })).rejects.toThrow("only a self-issued credential (urn:kya-brasil:self) takes co-signatures");
    await expect(add({ ...issued, credential: { ...issued.credential, principal: undefined } })).rejects.toThrow("only a company credential takes co-signatures of its legal representatives");
    for (const now of [undefined, new Date("x"), "2026-11-04T12:00:00Z", NOW.getTime()]) await expect(add(issued, cms, [], { anchors, now })).rejects.toThrow("opts.now must be a valid Date (the clock is the caller's)");
    await expect(add(issued, cms, [], null)).rejects.toThrow("opts.now must be a valid Date");
    for (const a of [undefined, [], "anchor", {}]) await expect(add(issued, cms, [], { anchors: a, now: NOW })).rejects.toThrow("opts.anchors: the ICP-Brasil trust anchors are required");
    for (const c of [null, 5, "", "  \n"]) await expect(add(issued, c)).rejects.toThrow("cms: the co-signature (base64 DER) is required");
    for (const chain of [null, "chain", {}]) await expect(add(issued, cms, chain)).rejects.toThrow("certChain must be an array; [] when the CMS already carries it");
    for (const p of [add(null), add(issued, "")]) await expect(p).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });

  it("records the co-signer's certificate by hash, with the caller's clock, after the ones already there", async () => {
    const { root, rep, other, anchors, text, issued } = await k();
    const one = await addCosignature(issued, await signerOf(other, root).sign(text), [], { anchors, now: NOW });
    const two = await addCosignature(one, await signerOf(rep, root).sign(text), [], { anchors, now: new Date("2026-11-05T08:00:00Z") });
    expect(two.credential.cosignatures).toHaveLength(2);
    expect(two.credential.cosignatures?.[0]).toEqual(one.credential.cosignatures?.[0]);
    expect(two.credential.cosignatures?.[1]).toEqual({ method: "icp-brasil-e-cpf", certificate_sha256: expect.stringMatching(/^[0-9a-f]{64}$/), issuer: root.cert.subject, signed_at: "2026-11-05T08:00:00.000Z", not_after: rep.cert.notAfter.toISOString() });
    expect(two.proof.cosignatures).toHaveLength(2);
    expect(two.proof.cosignatures?.[0]).toBe(one.proof.cosignatures?.[0]);
    expect(two.proof.text).toBe(issued.proof.text);
    expect(issued.credential.cosignatures).toBeUndefined();
    expect(one.credential.cosignatures).toHaveLength(1);
  });

  it("requires a whole number of co-signers and a source of representatives", async () => {
    const { anchors, issued } = await k();
    for (const minCosigners of [0, -1, 1.5, "2", Number.NaN]) await expect(verifyCompanyWill(issued, { anchors, now: NOW, representatives: reps, minCosigners: minCosigners as number })).rejects.toThrow("minCosigners must be an integer >= 1");
    for (const representatives of [[REP], REP, {}, null]) await expect(verifyCompanyWill(issued, { anchors, now: NOW, representatives: representatives as never })).rejects.toThrow("representatives must be (cnpj) => CPFs of the company's legal representatives");
    for (const opts of [{ anchors, now: NOW }, { anchors, now: NOW, acceptCertificateResponsible: "yes" }, { anchors, now: NOW, acceptCertificateResponsible: false }]) await expect(verifyCompanyWill(issued, opts as never)).rejects.toThrow("a source of legal representatives is required");
    expect(await verifyCompanyWill({ ...issued, credential: { ...issued.credential, principal: undefined } } as never, { anchors, now: NOW, representatives: reps })).toEqual({ ok: false, code: "COMPANY_SIGNATURE_INVALID", detail: "not a company credential", representatives_counted: 0, cosigners: [] });
    expect(await verifyCompanyWill(null as never, { anchors, now: NOW, representatives: reps })).toMatchObject({ ok: false, code: "COMPANY_SIGNATURE_INVALID", detail: "not a company credential" });
  });

  it("says what it counted, and what each co-signer is", async () => {
    const { root, rep, other, anchors, text, issued } = await k();
    const none = await verifyCompanyWill(issued, { anchors, now: NOW, representatives: reps });
    expect(none).toEqual({ ok: false, code: "NO_COSIGNATURE", detail: "the credential carries no co-signature by a legal representative (e-CPF)", representatives_counted: 0, cosigners: [] });

    const byOther = await addCosignature(issued, await signerOf(other, root).sign(text), [], { anchors, now: NOW });
    const notRep = await verifyCompanyWill(byOther, { anchors, now: NOW, representatives: reps });
    expect(notRep).toMatchObject({ ok: false, code: "COSIGNER_NOT_REPRESENTATIVE", detail: `no co-signer is a legal representative of CNPJ ${CNPJ}`, representatives_counted: 0 });
    expect(notRep.cosigners).toEqual([{ certificate_sha256: byOther.credential.cosignatures?.[0]?.certificate_sha256, ok: false, representative: false, code: "COSIGNER_NOT_REPRESENTATIVE", detail: `the co-signer is not a legal representative of CNPJ ${CNPJ}`, revocation: expect.objectContaining({ serial_number: "4" }) }]);

    const both = await addCosignature(byOther, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
    const one = await verifyCompanyWill(both, { anchors, now: NOW, representatives: (() => [Number(REP)]) as never });
    expect(one).toMatchObject({ ok: true, detail: "1 legal representative(s) co-signed", representatives_counted: 1 });
    expect(one.cosigners.map((c) => [c.ok, c.representative, c.basis, c.code, c.detail])).toEqual([
      [false, false, undefined, "COSIGNER_NOT_REPRESENTATIVE", `the co-signer is not a legal representative of CNPJ ${CNPJ}`],
      [true, true, "representatives", undefined, "valid co-signature by a legal representative"]
    ]);
    const short = await verifyCompanyWill(both, { anchors, now: NOW, representatives: reps, minCosigners: 2 });
    expect(short).toMatchObject({ ok: false, code: "INSUFFICIENT_COSIGNERS", detail: "1 of 2 required legal representatives co-signed", representatives_counted: 1 });
    expect(short.cosigners).toHaveLength(2);
    expect(await verifyCompanyWill(both, { anchors, now: NOW, representatives: () => [REP, OTHER], minCosigners: 2 })).toMatchObject({ ok: true, detail: "2 legal representative(s) co-signed", representatives_counted: 2 });
    await expect(verifyCompanyWill(both, { anchors, now: NOW, representatives: () => [REP, OTHER], minCosigners: 3 })).resolves.toMatchObject({ code: "INSUFFICIENT_COSIGNERS", detail: "2 of 3 required legal representatives co-signed" });
  });

  it("counts a person once, whatever the number of certificates they co-sign with", async () => {
    const { root, rep, anchors, text, issued } = await k();
    const second = await leaf(root, { cpf: REP }, "07");
    const one = await addCosignature(issued, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
    const two = await addCosignature(one, await signerOf(second, root).sign(text), [], { anchors, now: NOW });
    expect(two.credential.cosignatures).toHaveLength(2);
    expect(await verifyCompanyWill(two, { anchors, now: NOW, representatives: reps })).toMatchObject({ ok: true, representatives_counted: 1 });
    expect(await verifyCompanyWill(two, { anchors, now: NOW, representatives: reps, minCosigners: 2 })).toMatchObject({ ok: false, code: "INSUFFICIENT_COSIGNERS", representatives_counted: 1 });
  });

  it("refuses any mismatch between the co-signatures the credential records and the ones the proof carries", async () => {
    const { root, rep, other, anchors, text, issued } = await k();
    const cs = await addCosignature(issued, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
    const hash = cs.credential.cosignatures?.[0]?.certificate_sha256;
    // Carried by the proof and not recorded by the credential.
    const unrecorded = await verifyCompanyWill({ credential: issued.credential, proof: cs.proof }, { anchors, now: NOW, representatives: reps });
    expect(unrecorded).toMatchObject({ ok: false, code: "COSIGNATURE_NOT_RECORDED", detail: "the credential does not record this co-signer's certificate", representatives_counted: 0 });
    expect(unrecorded.cosigners).toEqual([{ certificate_sha256: hash, ok: false, representative: false, code: "COSIGNATURE_NOT_RECORDED", detail: "the credential does not record this co-signer's certificate", revocation: expect.objectContaining({ serial_number: "3" }) }]);
    // Recorded by the credential and not carried by the proof.
    const uncarried = await verifyCompanyWill({ credential: cs.credential, proof: issued.proof }, { anchors, now: NOW, representatives: reps });
    expect(uncarried).toMatchObject({ ok: false, code: "COSIGNATURE_NOT_RECORDED", detail: "the credential records a co-signature the proof does not carry (or it did not verify)" });
    expect(uncarried.cosigners).toEqual([{ certificate_sha256: hash, ok: false, representative: false, code: "COSIGNATURE_NOT_RECORDED", detail: "the credential records a co-signature the proof does not carry (or it did not verify)", revocation: null }]);
    // A valid co-signature next to a broken one is still a refusal, and the valid one is still counted.
    const extra = { credential: cs.credential, proof: { ...cs.proof, cosignatures: [...(cs.proof.cosignatures ?? []), await signerOf(other, root).sign(text)] } };
    expect(await verifyCompanyWill(extra, { anchors, now: NOW, representatives: reps })).toMatchObject({ ok: false, code: "COSIGNATURE_NOT_RECORDED", representatives_counted: 1 });
    const garbage = { credential: cs.credential, proof: { ...cs.proof, cosignatures: ["AAAA"] } };
    const bad = await verifyCompanyWill(garbage, { anchors, now: NOW, representatives: reps });
    expect(bad).toMatchObject({ ok: false, code: "COSIGNATURE_TEXT_MISMATCH" });
    expect(bad.cosigners[0]).toMatchObject({ certificate_sha256: null, ok: false, representative: false, code: "COSIGNATURE_TEXT_MISMATCH", revocation: null });
    expect(bad.cosigners[1]).toMatchObject({ certificate_sha256: hash, code: "COSIGNATURE_NOT_RECORDED" });
  });

  it("a representative's credential says how many signed, and needs the list", async () => {
    const { issued, anchors } = await rk();
    expect(await verifyCompanyWill(issued, { anchors, now: NOW, representatives: reps })).toEqual({ ok: true, detail: "1 legal representative(s) signed", representatives_counted: 1, cosigners: [] });
    expect(await verifyCompanyWill(issued, { anchors, now: NOW, acceptCertificateResponsible: true })).toEqual({ ok: false, code: "COMPANY_SIGNATURE_INVALID", detail: "a company credential signed by a legal representative needs representatives(cnpj): there is no e-CNPJ to name a person responsible", representatives_counted: 0, cosigners: [] });
    const notListed = await verifyCompanyWill(issued, { anchors, now: NOW, representatives: () => [OTHER] });
    expect(notListed).toMatchObject({ ok: false, code: "COMPANY_SIGNATURE_INVALID", representatives_counted: 0, cosigners: [] });
    expect(notListed.detail).toBe(`representative: the signer is not a legal representative of CNPJ ${CNPJ} in the verifier's list`);
  });
});
