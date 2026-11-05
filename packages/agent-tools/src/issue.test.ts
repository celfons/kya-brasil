/// <reference types="node" />
/**
 * kya-sign --issue / --cosign end to end with a mocked token: openToken is replaced by an in-memory signer over the
 * throwaway ICP-Brasil test chain (the same ecnpjSigner the token path builds), so the CLI runs buildMandate ->
 * mandateSigningInput -> token.sign -> assembleCredential, then addCosignature with an e-CPF. Real tokens are
 * covered by pkcs11.test.ts (SoftHSM2).
 */
import "reflect-metadata";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { OID_ICP_CNPJ, OID_ICP_PERSON, type IssuedCredential, ecnpjSigner, verifyCompanyWill, verifySelfIssuedCredential } from "@kya-brasil/core";
import { cosignCredential, parseAnchors, parseMandateInput } from "./issue";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const CNPJ = "11222333000181";
const CPF = "52998224725";

type Pair = { keys: CryptoKeyPair; cert: x509.X509Certificate };
let root: Pair, company: Pair, person: Pair;
const opened: { library: string; kind?: string; pin: string; closed: boolean }[] = [];

async function leaf(kind: "company" | "person", serial: string): Promise<Pair> {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const other = kind === "person"
    ? new OtherName({ typeId: OID_ICP_PERSON, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(`01011990${CPF}00000000000000000000000000000`))) })
    : new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(CNPJ))) });
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
  const subject = kind === "person" ? `CN=MARIA DA SILVA:${CPF}, O=ICP-Brasil, C=BR` : `CN=ACME LTDA:${CNPJ}, O=ICP-Brasil, C=BR`;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: serial, subject, issuer: root.cert.subject, notBefore: new Date("2025-01-01"), notAfter: new Date("2035-01-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: root.keys.privateKey, extensions: [san] });
  return { keys, cert };
}
const signerOf = (l: Pair) =>
  ecnpjSigner({ certificates: [new Uint8Array(l.cert.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", l.keys.privateKey, d.slice().buffer as ArrayBuffer)) });

// The mocked token: what openToken would return for the e-CNPJ or (kind "person") the e-CPF on the device.
vi.mock("./pkcs11.js", () => ({
  listTokenCertificates: async () => [],
  openToken: async (o: { library: string; kind?: string; pin: string }) => {
    const rec = { ...o, closed: false };
    opened.push(rec);
    return { ...signerOf(o.kind === "person" ? person : company), close: () => void (rec.closed = true) };
  }
}));

beforeAll(async () => {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date("2025-01-01"), notAfter: new Date("2035-01-01"), signingAlgorithm: alg, keys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  root = { keys, cert };
  company = await leaf("company", "02");
  person = await leaf("person", "03");
});
afterEach(() => {
  delete process.env.KYA_TOKEN_PIN;
  vi.restoreAllMocks();
});

function files() {
  const dir = mkdtempSync(join(tmpdir(), "kya-issue-"));
  const now = new Date();
  const day = 86400_000;
  writeFileSync(join(dir, "icp.pem"), root.cert.toString("pem"));
  writeFileSync(join(dir, "mandate-input.json"), JSON.stringify({
    credential_id: "cred-cli-1",
    agent: { kind: "evm", id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" },
    principal: { kind: "company", cnpj: "11.222.333/0001-81" },
    mandate: { actions: ["pay"], max_per_operation: { amount: 100, currency: "BRL" }, max_per_day: { amount: 500, currency: "BRL" }, currencies: ["BRL"], counterparties: [], payment_instruments: [], valid_from: new Date(now.getTime() - day).toISOString(), valid_until: new Date(now.getTime() + 30 * day).toISOString(), delegation: null },
    ttl_seconds: 7 * 86400
  }));
  return dir;
}

describe("kya-sign --issue / --cosign (mocked token)", () => {
  it("issues on the token, then a representative co-signs with an e-CPF", async () => {
    const { main } = await import("./cli");
    const dir = files();
    const err = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    process.env.KYA_TOKEN_PIN = "1234";
    await main(["--pkcs11", "/usr/lib/fake.so", "--issue", join(dir, "mandate-input.json"), "--anchors", join(dir, "icp.pem"), "--out", join(dir, "credential.json")]);
    expect(opened.at(-1)).toMatchObject({ library: "/usr/lib/fake.so", kind: "company", pin: "1234", closed: true });
    const issued = JSON.parse(readFileSync(join(dir, "credential.json"), "utf8")) as IssuedCredential;
    expect(issued.credential).toMatchObject({ credential_id: "cred-cli-1", issuer: "urn:kya-brasil:self", principal: { cnpj: CNPJ } });
    const anchors = parseAnchors(readFileSync(join(dir, "icp.pem"), "utf8"));
    expect((await verifySelfIssuedCredential({ ...issued, anchors, now: new Date() })).ok).toBe(true);
    // The holder saw exactly what was signed.
    expect(err.mock.calls.map((c) => String(c[0])).join("")).toContain("challenge: cred-cli-1");

    await main(["--pkcs11", "/usr/lib/fake.so", "--cosign", join(dir, "credential.json"), "--anchors", join(dir, "icp.pem")]);
    expect(opened.at(-1)).toMatchObject({ kind: "person", closed: true });
    const cosigned = JSON.parse(readFileSync(join(dir, "credential.json"), "utf8")) as IssuedCredential;
    expect(cosigned.credential.cosignatures).toHaveLength(1);
    expect(JSON.stringify(cosigned.credential)).not.toContain(CPF);
    expect(await verifyCompanyWill(cosigned, { anchors, now: new Date(), representatives: () => [CPF] })).toMatchObject({ ok: true });
    expect(await verifyCompanyWill(cosigned, { anchors, now: new Date(), representatives: () => [] })).toMatchObject({ ok: false, code: "COSIGNER_NOT_REPRESENTATIVE" });
  });

  it("co-signing with the company's e-CNPJ is refused", async () => {
    const dir = files();
    const { main } = await import("./cli");
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    process.env.KYA_TOKEN_PIN = "1234";
    await main(["--pkcs11", "/usr/lib/fake.so", "--issue", join(dir, "mandate-input.json"), "--anchors", join(dir, "icp.pem"), "--out", join(dir, "c.json")]);
    const issued = JSON.parse(readFileSync(join(dir, "c.json"), "utf8")) as IssuedCredential;
    await expect(cosignCredential({ issued, signer: signerOf(company), anchors: [root.cert.toString("pem")], now: new Date(), io: { log: () => undefined } })).rejects.toMatchObject({ code: "CERTIFICATE_INVALID" });
  });

  it("parses inputs: PEM bundles, base64 DER, the clock", () => {
    expect(parseAnchors(`${root.cert.toString("pem")}\n${company.cert.toString("pem")}`)).toHaveLength(2);
    expect(parseAnchors(" MIIB ")).toEqual(["MIIB"]);
    expect(() => parseAnchors("  ")).toThrow(/empty/);
    const clock = new Date("2026-11-04T00:00:00Z");
    expect(parseMandateInput("{}", clock).now).toBe(clock);
    expect(parseMandateInput('{"now":"2026-01-01T00:00:00Z"}', clock).now.toISOString()).toBe("2026-01-01T00:00:00.000Z");
    expect(() => parseMandateInput("[", clock)).toThrow(/not JSON/);
    expect(() => parseMandateInput('{"now":"x"}', clock)).toThrow(/not a date/);
  });
});
