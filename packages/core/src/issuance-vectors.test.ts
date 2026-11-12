/// <reference types="node" /> // test-only: Buffer, node:fs, process
/**
 * Test vectors for issuance by the principal (D-37, docs/SPEC.md section 20), kept in
 * docs/vectors/self-issued-v1.json so other implementations can check that they build the same signing input and
 * accept the same credential. A throwaway ICP-Brasil test chain (never a real certificate; no private key is
 * written). Regenerate with GEN_VECTORS=1 (new keys, same inputs).
 */
import "reflect-metadata";
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { ecnpjSigner } from "./ecnpj-sign.js";
import { OID_ICP_CNPJ, OID_ICP_PERSON } from "./icp-brasil.js";
import { type BuiltMandate, type MandateInput, assembleCredential, buildMandate, mandateSigningInput, verifySelfIssuedCredential } from "./issuance.js";
import { type Credential, REPRESENTATIVE_METHOD } from "./types.js";

const FILE = new URL("../../../docs/vectors/self-issued-v1.json", import.meta.url);
const FILE_REPRESENTATIVE = new URL("../../../docs/vectors/self-issued-representative-v1.json", import.meta.url);
/** GEN_VECTORS=1 writes both files; GEN_VECTORS=<name> writes one, and leaves the keys of the other as they are. */
const regenerate = (name: string) => process.env.GEN_VECTORS === "1" || process.env.GEN_VECTORS === name;
// A CPF with valid check digits that belongs to no one in this test chain: the verifier's list in the vector.
const REPRESENTATIVE_CPF = "52998224725";
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");

const INPUT = {
  credential_id: "7e1d2c3b-0000-4000-8000-000000000037",
  agent: { kind: "evm", id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" },
  principal: { kind: "company", cnpj: "11.222.333/0001-81" },
  mandate: {
    actions: ["quote", "order", "pay"],
    max_per_operation: { amount: 5000, currency: "BRL" },
    max_per_day: { amount: 20000, currency: "BRL" },
    currencies: ["BRL"],
    counterparties: ["33000167000101", "*.beta.com.br"],
    payment_instruments: [],
    valid_from: "2026-11-01T00:00:00Z",
    valid_until: "2027-03-01T00:00:00Z",
    delegation: { max_depth: 1, max_ttl_seconds: 3600 },
    notes: "free-form fields are kept but not evaluated"
  },
  ttl_seconds: 30 * 86400,
  now: "2026-11-04T12:00:00.000Z"
} as const;

async function generate() {
  x509.cryptoProvider.set(globalThis.crypto as Crypto);
  const caKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste KYA (vetores), O=ICP-Brasil TESTE, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2031-01-01"), signingAlgorithm: alg, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode("11222333000181"))) }) })])));
  const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "37", subject: "CN=ACME LTDA:11222333000181, O=ICP-Brasil TESTE, C=BR", issuer: ca.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: caKeys.privateKey, extensions: [san] });
  const now = new Date(INPUT.now);
  const built = await buildMandate({ ...INPUT, now } as unknown as MandateInput);
  const signing = await mandateSigningInput(built);
  const signer = ecnpjSigner({ certificates: [new Uint8Array(leaf.rawData), new Uint8Array(ca.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, d.slice().buffer as ArrayBuffer)) });
  const issued = await assembleCredential(built, await signer.sign(signing.text), [], { anchors: [b64(ca.rawData)], now });
  return {
    spec: "KYA Brasil: issuance by the principal (D-37, SPEC section 20)",
    note: "Throwaway test chain, not ICP-Brasil. Verify at `verify_at` with `anchors`; no private key is included.",
    anchors: [b64(ca.rawData)],
    verify_at: INPUT.now,
    input: INPUT,
    built,
    signing_input: { text: signing.text, sha256: signing.sha256 },
    credential: issued.credential,
    proof: issued.proof,
    tampered: { ...issued.credential, mandate: { ...issued.credential.mandate, max_per_day: { amount: 200000, currency: "BRL" } } }
  };
}

/** The same mandate signed by a legal representative's e-CPF alone (D-43, SPEC section 22). */
async function generateRepresentative() {
  x509.cryptoProvider.set(globalThis.crypto as Crypto);
  const caKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste KYA (vetores), O=ICP-Brasil TESTE, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2031-01-01"), signingAlgorithm: alg, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const person = new OtherName({ typeId: OID_ICP_PERSON, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(`01011990${REPRESENTATIVE_CPF}00000000000000000000000000000`))) });
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: person })])));
  const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "38", subject: `CN=REPRESENTANTE DE TESTE:${REPRESENTATIVE_CPF}, O=ICP-Brasil TESTE, C=BR`, issuer: ca.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-06-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: caKeys.privateKey, extensions: [san] });
  const now = new Date(INPUT.now);
  const input = { ...INPUT, credential_id: "7e1d2c3b-0000-4000-8000-000000000038", principal: { ...INPUT.principal, signed_by: "representative" } };
  const built = await buildMandate({ ...input, now } as unknown as MandateInput);
  const signing = await mandateSigningInput(built);
  const signer = ecnpjSigner({ certificates: [new Uint8Array(leaf.rawData), new Uint8Array(ca.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, d.slice().buffer as ArrayBuffer)) });
  const representatives = [REPRESENTATIVE_CPF];
  const issued = await assembleCredential(built, await signer.sign(signing.text), [], { anchors: [b64(ca.rawData)], now, representatives: () => representatives });
  return {
    spec: "KYA Brasil: company mandate signed by a legal representative (D-43, SPEC section 22)",
    note: "Throwaway test chain, not ICP-Brasil, and a CPF that belongs to no one. Verify at `verify_at` with `anchors` and with `representatives` as the verifier's list for the CNPJ; with no list the credential is refused. No private key is included.",
    anchors: [b64(ca.rawData)],
    verify_at: INPUT.now,
    representatives,
    input,
    built,
    signing_input: { text: signing.text, sha256: signing.sha256 },
    credential: issued.credential,
    proof: issued.proof,
    tampered: { ...issued.credential, mandate: { ...issued.credential.mandate, max_per_day: { amount: 200000, currency: "BRL" } } }
  };
}

describe("issuance test vectors (D-37)", () => {
  it("docs/vectors/self-issued-v1.json: same signing input from the same input, the credential verifies, the tampered copy does not", async () => {
    if (regenerate("self-issued")) writeFileSync(FILE, JSON.stringify(await generate(), null, 2) + "\n");
    const v = JSON.parse(readFileSync(FILE, "utf8")) as Awaited<ReturnType<typeof generate>>;
    const now = new Date(v.verify_at);
    const built = await buildMandate({ ...v.input, now } as unknown as MandateInput);
    expect(built).toEqual(v.built);
    expect(await mandateSigningInput(built as BuiltMandate)).toMatchObject(v.signing_input);
    expect(v.proof.text).toBe(v.signing_input.text);
    const ok = await verifySelfIssuedCredential({ credential: v.credential as Credential, proof: v.proof, anchors: v.anchors, now });
    expect(ok.checks.filter((c) => !c.ok)).toEqual([]);
    const bad = await verifySelfIssuedCredential({ credential: v.tampered as Credential, proof: v.proof, anchors: v.anchors, now });
    expect(bad.checks.filter((c) => !c.ok).map((c) => c.rule)).toEqual(["mandate"]);
  });

  it("docs/vectors/self-issued-representative-v1.json: the representative's form verifies against the verifier's list, and only against it", async () => {
    if (regenerate("representative")) writeFileSync(FILE_REPRESENTATIVE, JSON.stringify(await generateRepresentative(), null, 2) + "\n");
    const v = JSON.parse(readFileSync(FILE_REPRESENTATIVE, "utf8")) as Awaited<ReturnType<typeof generateRepresentative>>;
    const now = new Date(v.verify_at);
    const built = await buildMandate({ ...v.input, now } as unknown as MandateInput);
    expect(built).toEqual(v.built);
    expect(await mandateSigningInput(built as BuiltMandate)).toMatchObject(v.signing_input);
    expect(v.proof.text).toBe(v.signing_input.text);
    expect(v.proof.text.split("\n").at(-1)).toBe("signed-by: legal representative (e-CPF)");
    const c = v.credential as Credential;
    expect(c.authorized_by.method).toBe(REPRESENTATIVE_METHOD);
    // The credential names the company and keeps the signer by hash only: no CPF and no name.
    expect(JSON.stringify(c)).not.toContain(REPRESENTATIVE_CPF);
    expect(JSON.stringify(c)).not.toContain("REPRESENTANTE");
    const verify = (credential: Credential, representatives?: () => string[]) => verifySelfIssuedCredential({ credential, proof: v.proof, anchors: v.anchors, now, representatives });
    const failing = async (r: ReturnType<typeof verify>) => (await r).checks.filter((x) => !x.ok).map((x) => x.rule);
    expect(await failing(verify(c, () => v.representatives))).toEqual([]);
    expect(await failing(verify(c))).toEqual(["representative"]);
    expect(await failing(verify(c, () => ["11144477735"]))).toEqual(["representative"]);
    expect(await failing(verify(v.tampered as Credential, () => v.representatives))).toEqual(["mandate"]);
  });
});
