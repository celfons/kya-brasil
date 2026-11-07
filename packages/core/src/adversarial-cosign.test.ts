/// <reference types="node" /> // test-only: Buffer, node:fs
/**
 * Adversarial vectors (H4), co-signature part: instances of docs/formal/adversarial.als over the co-signature
 * sections of threats.als, written to docs/vectors/adversarial-v1.json. Each vector describes a company mandate
 * with (or without) one e-CPF co-signature and says whether verifyCompanyWill must accept it, or with which code it
 * must refuse. The two trust assumptions the library cannot see (a stale representatives list, a lent e-CPF) are
 * vectors it must ACCEPT; the test keeps them so that the assumption stays written down.
 */
import "reflect-metadata";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { privateKeyToAccount } from "viem/accounts";
import { ecnpjSigner } from "./ecnpj-sign.js";
import { OID_ICP_CNPJ, OID_ICP_PERSON, OID_ICP_RESPONSIBLE } from "./icp-brasil.js";
import { type MandateInput, assembleCredential, buildMandate, mandateSigningInput } from "./issuance.js";
import { addCosignature, verifyCompanyWill } from "./cosign.js";

interface CosignVector {
  command: string; solution: number; source: string; kind: "cosign"; mode: "list" | "responsible";
  has_cosigner: boolean; same_text: boolean; cosigner_listed?: boolean; cosigner_is_responsible?: boolean;
  cosigner_operated_by_owner?: boolean; cosigner_owner_is_real_rep?: boolean;
  expected: { ok: boolean; code?: string; assumption?: string };
}
const FILE = new URL("../../../docs/vectors/adversarial-v1.json", import.meta.url);
const { vectors } = JSON.parse(readFileSync(FILE, "utf8")) as { vectors: ({ kind: string } & CosignVector)[] };
const cosigns = vectors.filter((v): v is CosignVector => v.kind === "cosign");

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const CNPJ = "11222333000181";
const REP = "52998224725"; // the co-signer's CPF in every vector
const OTHER = "11144477735"; // a CPF that is neither the co-signer nor, when the vector says so, the responsible
const NOW = new Date("2026-11-04T12:00:00Z");
const AGENT = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

type Pair = { keys: CryptoKeyPair; cert: x509.X509Certificate };
async function ca(): Promise<Pair> {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  return { keys, cert };
}
async function leaf(root: Pair, who: { cnpj?: string; cpf?: string; responsible?: string }, serial: string): Promise<Pair> {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const on = (typeId: string, v: string) => new OtherName({ typeId, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(v))) });
  const others = who.cpf ? [on(OID_ICP_PERSON, `01011990${who.cpf}00000000000000000000000000000`)] : [on(OID_ICP_CNPJ, who.cnpj!), ...(who.responsible ? [on(OID_ICP_RESPONSIBLE, `01011980${who.responsible}00000000000000000000000000000`)] : [])];
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames(others.map((o) => new GeneralName({ otherName: o })))));
  const subject = who.cpf ? `CN=FULANO DE TAL:${who.cpf}, O=ICP-Brasil, C=BR` : `CN=ACME LTDA:${who.cnpj}, O=ICP-Brasil, C=BR`;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: serial, subject, issuer: root.cert.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: root.keys.privateKey, extensions: [san, new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true)] });
  return { keys, cert };
}
const signerOf = (l: Pair, root: Pair) => ecnpjSigner({ certificates: [new Uint8Array(l.cert.rawData), new Uint8Array(root.cert.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", l.keys.privateKey, d.slice().buffer as ArrayBuffer)) });

const input: MandateInput = {
  credential_id: "cred-h4-cosign", agent: { kind: "evm", id: AGENT.address }, principal: { kind: "company", cnpj: CNPJ },
  mandate: { actions: ["pay"], max_per_operation: { amount: 100, currency: "BRL" }, max_per_day: { amount: 500, currency: "BRL" }, currencies: ["BRL"], counterparties: [], payment_instruments: [], valid_from: "2026-11-01T00:00:00Z", valid_until: "2027-03-01T00:00:00Z", delegation: null },
  ttl_seconds: 7 * 86400, now: NOW
};

/** Two PKIs, built once: the e-CNPJ naming REP as responsible, and the e-CNPJ naming OTHER. */
const pkis = new Map<boolean, Promise<{ root: Pair; rep: Pair; anchors: string[]; text: string; issued: Awaited<ReturnType<typeof assembleCredential>> }>>();
function pki(responsibleIsRep: boolean) {
  if (!pkis.has(responsibleIsRep)) pkis.set(responsibleIsRep, (async () => {
    const root = await ca();
    const company = await leaf(root, { cnpj: CNPJ, responsible: responsibleIsRep ? REP : OTHER }, "02");
    const rep = await leaf(root, { cpf: REP }, "03");
    const anchors = [b64(root.cert.rawData)];
    const built = await buildMandate(input);
    const { text } = await mandateSigningInput(built);
    const issued = await assembleCredential(built, await signerOf(company, root).sign(text), [], { anchors, now: NOW });
    return { root, rep, anchors, text, issued };
  })());
  return pkis.get(responsibleIsRep)!;
}

describe("adversarial vectors (H4): co-signature by a legal representative", () => {
  it("has vectors of every command", () => {
    const commands = new Set(cosigns.map((v) => v.command));
    for (const c of ["CosignListedSameText", "CosignNotListed", "CosignOtherText", "CosignAbsent", "CosignByResponsible", "CosignStaleList", "CosignLentECpf"]) expect(commands.has(c), c).toBe(true);
  });

  for (const v of cosigns) {
    it(`${v.command} #${v.solution}: ${v.expected.ok ? "accepted" : v.expected.code}${v.expected.assumption ? ` (assumes ${v.expected.assumption})` : ""}`, async () => {
      const { root, rep, anchors, text, issued } = await pki(v.cosigner_is_responsible === true);
      let subject = issued;
      if (v.has_cosigner) {
        const good = await addCosignature(issued, await signerOf(rep, root).sign(text), [], { anchors, now: NOW });
        // A co-signature over another text cannot be added (addCosignature refuses it), so it is smuggled into the proof.
        subject = v.same_text ? good : { credential: good.credential, proof: { ...good.proof, cosignatures: [await signerOf(rep, root).sign(text.replace("cred-h4-cosign", "cred-h4-other"))] } };
      }
      const opts = v.mode === "list"
        ? { anchors, now: NOW, representatives: () => (v.cosigner_listed ? [REP] : [OTHER]) }
        : { anchors, now: NOW, acceptCertificateResponsible: true };
      const r = await verifyCompanyWill(subject, opts);
      expect(r.ok).toBe(v.expected.ok);
      if (!v.expected.ok) expect(r.code).toBe(v.expected.code);
    });
  }
});
