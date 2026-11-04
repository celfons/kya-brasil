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
import { OID_ICP_CNPJ } from "./icp-brasil.js";
import { type BuiltMandate, type MandateInput, assembleCredential, buildMandate, mandateSigningInput, verifySelfIssuedCredential } from "./issuance.js";
import type { Credential } from "./types.js";

const FILE = new URL("../../../docs/vectors/self-issued-v1.json", import.meta.url);
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

describe("issuance test vectors (D-37)", () => {
  it("docs/vectors/self-issued-v1.json: same signing input from the same input, the credential verifies, the tampered copy does not", async () => {
    if (process.env.GEN_VECTORS) writeFileSync(FILE, JSON.stringify(await generate(), null, 2) + "\n");
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
});
