/// <reference types="node" /> // test-only: Buffer
/**
 * Issuance by the principal (D-37): round trip build -> signing input -> sign -> assemble -> verify, tampering,
 * refusals, and property tests (every credential issued from a valid input verifies; every input verification
 * would refuse is refused at issuance, delegation included). Throwaway ICP-Brasil test chain, never real
 * certificates; the in-memory signer is ecnpjSigner over a WebCrypto key (the same path as an A1 file).
 */
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import * as pkijs from "pkijs";
import { privateKeyToAccount } from "viem/accounts";
import { canonicalize } from "./attestation.js";
import { checkAction, validateMandate } from "./mandate.js";
import { mandateSha256, verifyMandateAuthorization } from "./credential.js";
import { type Delegation, delegationText, verifyDelegationChain } from "./delegation.js";
import { buildDetachedCms, ecnpjSigner } from "./ecnpj-sign.js";
import { OID_ICP_CNPJ, OID_ICP_PERSON } from "./icp-brasil.js";
import { MANDATE_REQUIRED_FIELDS, type MandateInput, type MandateTerms, SELF_ISSUER, assembleCredential, assembleDelegation, buildDelegation, buildMandate, mandateSigningInput, verifySelfIssuedCredential, withCertificates } from "./issuance.js";
import { encodePrincipalProofHeader, decodePrincipalProofHeader, verifyPrincipalProof } from "./principal-proof.js";
import type { Credential } from "./types.js";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString("base64");
const CNPJ = "11222333000181";
const CPF = "52998224725";
const NOW = new Date("2026-11-04T12:00:00Z");
const AGENT = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const SUB = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

async function ca(name = "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR") {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name, notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys, extensions: [new x509.BasicConstraintsExtension(true, 1, true)] });
  return { keys, cert };
}

async function leaf(root: Awaited<ReturnType<typeof ca>>, kind: "company" | "person", opts: { cnpj?: string; serial?: string; notAfter?: Date } = {}) {
  const keys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cnpj = opts.cnpj ?? CNPJ;
  const other = kind === "person"
    ? new OtherName({ typeId: OID_ICP_PERSON, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(`01011990${CPF}00000000000000000000000000000`))) })
    : new OtherName({ typeId: OID_ICP_CNPJ, value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(cnpj))) });
  const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
  const subject = kind === "person" ? `CN=MARIA DA SILVA:${CPF}, O=ICP-Brasil, C=BR` : `CN=ACME LTDA:${cnpj}, O=ICP-Brasil, C=BR`;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: opts.serial ?? "02", subject, issuer: root.cert.subject, notBefore: new Date("2026-01-01"), notAfter: opts.notAfter ?? new Date("2027-06-01"), signingAlgorithm: alg, publicKey: keys.publicKey, signingKey: root.keys.privateKey, extensions: [san] });
  return { keys, cert };
}

/** A1-like in-memory signer: the certificate chain and a WebCrypto RSA key, through the core's own CMS builder. */
const signerOf = (l: Awaited<ReturnType<typeof leaf>>, root: Awaited<ReturnType<typeof ca>>) =>
  ecnpjSigner({ certificates: [new Uint8Array(l.cert.rawData), new Uint8Array(root.cert.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", l.keys.privateKey, d.slice().buffer as ArrayBuffer)) });

const terms = (over: Partial<MandateTerms> = {}): MandateTerms => ({
  actions: ["quote", "order", "pay"],
  max_per_operation: { amount: 5000, currency: "BRL" },
  max_per_day: { amount: 20000, currency: "BRL" },
  currencies: ["BRL"],
  counterparties: ["33000167000101", "*.beta.com.br"],
  payment_instruments: [],
  valid_from: "2026-11-01T00:00:00Z",
  valid_until: "2027-03-01T00:00:00Z",
  delegation: { max_depth: 2, max_ttl_seconds: 3600 },
  ...over
});

const input = (over: Partial<MandateInput> = {}): MandateInput => ({
  credential_id: "cred-0001",
  agent: { kind: "evm", id: AGENT.address },
  principal: { kind: "company", cnpj: "11.222.333/0001-81" },
  mandate: terms(),
  ttl_seconds: 30 * 86400,
  now: NOW,
  ...over
});

let pkiCache: Promise<{ root: Awaited<ReturnType<typeof ca>>; company: Awaited<ReturnType<typeof leaf>>; person: Awaited<ReturnType<typeof leaf>>; anchors: string[] }> | null = null;
const pki = () => (pkiCache ??= (async () => {
  const root = await ca();
  return { root, company: await leaf(root, "company"), person: await leaf(root, "person", { serial: "03" }), anchors: [b64(root.cert.rawData)] };
})());

/** The whole issuance, as a principal with an A1 certificate would run it. */
async function issue(i: MandateInput = input()) {
  const k = await pki();
  const built = await buildMandate(i);
  const { text } = await mandateSigningInput(built);
  const cms = await signerOf(i.principal.kind === "person" ? k.person : k.company, k.root).sign(text);
  return { k, built, issued: await assembleCredential(built, cms, [], { anchors: k.anchors, now: NOW }) };
}

const failed = (r: { checks: { rule: string; ok: boolean }[] }) => r.checks.filter((c) => !c.ok).map((c) => c.rule);

describe("issuance by the principal (D-37): round trip", () => {
  it("build -> signing input -> sign with the test chain -> assemble -> verify is accepted", async () => {
    const { k, built, issued } = await issue();
    const { credential, proof } = issued;
    expect(credential.issuer).toBe(SELF_ISSUER);
    expect(credential.principal).toMatchObject({ cnpj: CNPJ, legal_name: "ACME LTDA", registration_status: "NOT_CHECKED" });
    expect(credential.authorized_by.mandate_sha256).toBe(await mandateSha256(built.mandate));
    expect(credential.attestation).toBeUndefined();
    expect(credential.expires_at <= built.expires_at).toBe(true);
    // The verifier's existing functions accept it, unchanged.
    expect(failed(await verifyPrincipalProof({ credential, proof, anchors: k.anchors, now: NOW }))).toEqual([]);
    expect(await verifyMandateAuthorization(credential)).toBe("signed");
    const r = await verifySelfIssuedCredential({ credential, proof, anchors: k.anchors, now: NOW });
    expect(failed(r)).toEqual([]);
    expect(r.revocation).toMatchObject({ serial_number: "2", crl_urls: [] });
    expect(checkAction(credential.mandate, { action: "pay", amount: 80, currency: "BRL", counterparty: "shop.beta.com.br", now: NOW }).allowed).toBe(true);
    expect(checkAction(credential.mandate, { action: "pay", amount: 8000, currency: "BRL", now: NOW }).allowed).toBe(false);
    // What the agent presents survives the header.
    expect(decodePrincipalProofHeader(encodePrincipalProofHeader(proof))).toEqual(proof);
  });

  it("the signing input is exactly the challenge text the verifier reads, with its UTF-8 bytes and SHA-256", async () => {
    const built = await buildMandate(input());
    const s = await mandateSigningInput(built);
    expect(s.text.split("\n")).toEqual([
      "KYA Brasil: prove this agent key acts for a company",
      `issuer: ${SELF_ISSUER}`,
      "challenge: cred-0001",
      `agent: evm:${AGENT.address}`,
      `cnpj: ${CNPJ}`,
      `mandate-sha256: ${built.mandate_sha256}`,
      `expires: ${built.expires_at}`
    ]);
    expect(new TextDecoder().decode(s.bytes)).toBe(s.text);
    expect(s.sha256).toBe(Buffer.from(await crypto.subtle.digest("SHA-256", s.bytes.slice().buffer as ArrayBuffer)).toString("hex"));
    expect(built.mandate_sha256).toBe(Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(built.mandate)))).toString("hex"));
    // Deterministic: same input, same bytes.
    expect((await mandateSigningInput(await buildMandate(input()))).text).toBe(s.text);
  });

  it("works for a person (e-CPF) and carries nothing personal", async () => {
    const { k, issued } = await issue(input({ principal: { kind: "person" } }));
    expect(issued.credential.principal).toEqual({ kind: "person", verified_by: "icp-brasil-e-cpf" });
    expect(failed(await verifySelfIssuedCredential({ ...issued, anchors: k.anchors, now: NOW }))).toEqual([]);
    expect(JSON.stringify(issued.credential)).not.toContain(CPF);
    expect(JSON.stringify(issued.credential)).not.toContain("MARIA");
  });

  it("takes a signature from an external signer that returns only the leaf, adding the chain", async () => {
    const k = await pki();
    const built = await buildMandate(input());
    const { text } = await mandateSigningInput(built);
    const leafOnly = await buildDetachedCms({ text, certificates: [new Uint8Array(k.company.cert.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", k.company.keys.privateKey, d.slice().buffer as ArrayBuffer)) });
    const issued = await assembleCredential(built, leafOnly, [k.root.cert.toString("pem")], { anchors: k.anchors, now: NOW });
    const signed = new pkijs.SignedData({ schema: pkijs.ContentInfo.fromBER(Buffer.from(issued.proof.cms, "base64")).content });
    expect(signed.certificates).toHaveLength(2);
    expect(failed(await verifySelfIssuedCredential({ ...issued, anchors: k.anchors, now: NOW }))).toEqual([]);
    expect(withCertificates(issued.proof.cms, [new Uint8Array(k.root.cert.rawData)])).toBe(issued.proof.cms); // nothing to add
  });
});

describe("issuance: tampering is refused", () => {
  it("changing any byte of the mandate is refused", async () => {
    const { k, issued } = await issue();
    const original = canonicalize(issued.credential.mandate);
    let tried = 0;
    for (let i = 0; i < original.length; i++) {
      const code = original.charCodeAt(i);
      const changed = original.slice(0, i) + String.fromCharCode(code === 0x7a ? 0x79 : code + 1) + original.slice(i + 1);
      let mandate: unknown;
      try {
        mandate = JSON.parse(changed);
      } catch {
        continue; // not JSON: cannot even be presented
      }
      if (canonicalize(mandate) === original) continue;
      tried++;
      const credential = { ...issued.credential, mandate } as Credential;
      const r = await verifySelfIssuedCredential({ credential, proof: issued.proof, anchors: k.anchors, now: NOW });
      expect(r.ok, `byte ${i}: ${changed}`).toBe(false);
      expect(failed(r)).toContain("mandate");
    }
    expect(tried).toBeGreaterThan(original.length / 2);
  }, 60_000);

  it("changing any byte of the signed text is refused, and so is any change to the credential's bound fields", async () => {
    const { k, issued } = await issue();
    const text = issued.proof.text;
    for (let i = 0; i < text.length; i++) {
      const changed = text.slice(0, i) + String.fromCharCode(text.charCodeAt(i) ^ 1) + text.slice(i + 1);
      expect((await verifyPrincipalProof({ credential: issued.credential, proof: { ...issued.proof, text: changed }, anchors: k.anchors, now: NOW })).ok, `byte ${i}`).toBe(false);
    }
    const tamper = async (c: Partial<Credential>) => failed(await verifySelfIssuedCredential({ credential: { ...issued.credential, ...c }, proof: issued.proof, anchors: k.anchors, now: NOW }));
    expect(await tamper({ credential_id: "cred-0002" })).toEqual(["credential"]);
    expect(await tamper({ expires_at: "2027-12-01T00:00:00.000Z" })).toEqual(["validity"]);
    expect(await tamper({ issuer: "https://kya.example" })).toEqual(expect.arrayContaining(["issuer", "credential"]));
    expect(await tamper({ agent: { kind: "evm", id: SUB.address } })).toEqual(["agent"]);
    expect(await tamper({ status: "revoked" })).toEqual(["validity"]);
    // Expired, and the clock before issuance.
    expect(failed(await verifySelfIssuedCredential({ ...issued, anchors: k.anchors, now: new Date("2027-01-01T00:00:00Z") }))).toEqual(["validity"]);
    expect(failed(await verifySelfIssuedCredential({ ...issued, anchors: k.anchors, now: new Date("2026-11-01T00:00:00Z") }))).toEqual(["validity"]);
  }, 60_000);
});

describe("issuance: refused when verification would refuse", () => {
  it("every risk field is required: none has a default", async () => {
    for (const field of MANDATE_REQUIRED_FIELDS) {
      const m = terms();
      delete (m as Record<string, unknown>)[field];
      await expect(buildMandate(input({ mandate: m })), field).rejects.toThrow(new RegExp(`missing ${field}`));
    }
    await expect(buildMandate(input({ mandate: terms({ actions: [] }) }))).rejects.toThrow(/at least one action/);
    for (const k of ["credential_id", "agent", "principal", "ttl_seconds", "now"] as const) {
      const i = input();
      delete (i as unknown as Record<string, unknown>)[k];
      await expect(buildMandate(i), k).rejects.toThrow();
    }
    // Explicit choices are accepted: [] = any, null = may not delegate.
    const built = await buildMandate(input({ mandate: terms({ counterparties: [], delegation: null }) }));
    expect(built.mandate.delegation).toBeUndefined();
  });

  it("refuses what the verifier's schema refuses, an ended mandate and a bad lifetime or id", async () => {
    await expect(buildMandate(input({ mandate: terms({ actions: ["Pay"] }) }))).rejects.toThrow(/actions/);
    await expect(buildMandate(input({ mandate: terms({ max_per_day: { amount: 0, currency: "BRL" } }) }))).rejects.toThrow(/max_per_day/);
    await expect(buildMandate(input({ mandate: terms({ valid_from: "2027-04-01T00:00:00Z" }) }))).rejects.toThrow(/after valid_from/);
    await expect(buildMandate(input({ mandate: terms({ valid_until: "2026-11-02T00:00:00Z", valid_from: "2026-10-01T00:00:00Z" }) }))).rejects.toThrow(/not after now/);
    await expect(buildMandate(input({ mandate: terms({ delegation: { max_depth: 4, max_ttl_seconds: 600 } }) }))).rejects.toThrow(/max_depth/);
    await expect(buildMandate(input({ mandate: terms({ payment_instruments: [{ network: "visa", ref_sha256: "4111111111111111" }] }) }))).rejects.toThrow(/card number/);
    await expect(buildMandate(input({ ttl_seconds: 0 }))).rejects.toThrow(/ttl_seconds/);
    await expect(buildMandate(input({ credential_id: "a\nissuer: x" }))).rejects.toThrow(/credential_id/);
    await expect(buildMandate(input({ principal: { kind: "company", cnpj: "11222333000180" } }))).rejects.toThrow(/valid CNPJ/);
    await expect(buildMandate(input({ agent: { kind: "evm", id: "0x1234" } }))).rejects.toThrow(/agent/);
  });

  it("refuses a mandate changed after building, another company's certificate, an untrusted chain and an expired certificate", async () => {
    const k = await pki();
    const built = await buildMandate(input());
    await expect(mandateSigningInput({ ...built, mandate: { ...built.mandate, max_per_day: { amount: 99999, currency: "BRL" } } })).rejects.toThrow(/changed after buildMandate/);
    const { text } = await mandateSigningInput(built);
    const other = await leaf(k.root, "company", { cnpj: "33000167000101", serial: "04" });
    const otherCms = await buildDetachedCms({ text, certificates: [new Uint8Array(other.cert.rawData)], sign: async (d) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", other.keys.privateKey, d.slice().buffer as ArrayBuffer)) });
    await expect(assembleCredential(built, otherCms, [], { anchors: k.anchors, now: NOW })).rejects.toThrow(/belongs to CNPJ/);
    const good = await signerOf(k.company, k.root).sign(text);
    const stranger = await ca("CN=AC Estranha, O=Outra, C=BR");
    await expect(assembleCredential(built, good, [], { anchors: [b64(stranger.cert.rawData)], now: NOW })).rejects.toThrow(/chain/);
    await expect(assembleCredential(built, good, [], { anchors: [], now: NOW })).rejects.toThrow(/anchors/);
    await expect(assembleCredential(built, good, [], { anchors: k.anchors, now: new Date("2027-07-01T00:00:00Z") })).rejects.toThrow(/valid from/);
    // A signature over another text (another mandate) does not assemble.
    const wider = await buildMandate(input({ mandate: terms({ max_per_operation: { amount: 50000, currency: "BRL" } }) }));
    await expect(assembleCredential(wider, good, [], { anchors: k.anchors, now: NOW })).rejects.toThrow(/does not match|digest/);
    // A person's certificate does not issue for a company, and vice versa.
    const personCms = await signerOf(k.person, k.root).sign(text);
    await expect(assembleCredential(built, personCms, [], { anchors: k.anchors, now: NOW })).rejects.toThrow(/e-CPF/);
  });

  it("the credential never outlives the certificate", async () => {
    const k = await pki();
    const short = await leaf(k.root, "company", { serial: "05", notAfter: new Date("2026-12-01T00:00:00Z") });
    const built = await buildMandate(input());
    const { text } = await mandateSigningInput(built);
    const issued = await assembleCredential(built, await signerOf(short, k.root).sign(text), [], { anchors: k.anchors, now: NOW });
    expect(issued.credential.expires_at).toBe("2026-12-01T00:00:00.000Z");
  });
});

describe("delegation: the parent agent issues its sub-agent's mandate", () => {
  const child = (over: Partial<MandateTerms> = {}) => terms({ actions: ["quote"], max_per_operation: { amount: 500, currency: "BRL" }, max_per_day: { amount: 1000, currency: "BRL" }, counterparties: ["shop.beta.com.br"], valid_until: "2027-02-01T00:00:00Z", delegation: null, ...over });

  it("build -> sign with the agent's key -> assemble -> verifyDelegationChain is accepted", async () => {
    const { issued } = await issue();
    const prepared = await buildDelegation(issued, { delegate: { kind: "evm", id: SUB.address }, mandate: child(), ttl_seconds: 600, now: NOW });
    const chain = await assembleDelegation(issued, prepared, await AGENT.signMessage({ message: prepared.text }), NOW);
    const r = await verifyDelegationChain({ credential: issued.credential, chain, now: NOW });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.delegate).toEqual({ kind: "evm", id: SUB.address });
  });

  it("refuses at issuance what the chain verification refuses", async () => {
    const { issued } = await issue();
    const d = (mandate: MandateTerms, ttl_seconds = 600, now = NOW) => buildDelegation(issued, { delegate: { kind: "evm", id: SUB.address }, mandate, ttl_seconds, now });
    await expect(d(child({ max_per_operation: { amount: 6000, currency: "BRL" } }))).rejects.toThrow(/broader.*max_per_operation/);
    await expect(d(child({ max_per_day: { amount: 30000, currency: "BRL" } }))).rejects.toThrow(/broader.*max_per_day/);
    await expect(d(child({ actions: ["sign"] }))).rejects.toThrow(/broader.*actions/);
    await expect(d(child({ counterparties: [] }))).rejects.toThrow(/broader.*counterparties/);
    await expect(d(child({ valid_until: "2027-06-01T00:00:00Z" }))).rejects.toThrow(/broader.*valid_until/);
    await expect(d(child({ delegation: { max_depth: 2, max_ttl_seconds: 600 } }))).rejects.toThrow(/broader.*max_depth/);
    await expect(d(child(), 7200)).rejects.toThrow(/ttlSeconds/);
    await expect(d(child(), 600, new Date("2027-06-01T00:00:00Z"))).rejects.toThrow(/not in force/);
    const m = child();
    delete (m as Record<string, unknown>).max_per_day;
    await expect(d(m)).rejects.toThrow(/missing max_per_day/);
    // The principal did not allow delegation.
    const { issued: closed } = await issue(input({ credential_id: "cred-closed", mandate: terms({ delegation: null }) }));
    await expect(buildDelegation(closed, { delegate: { kind: "evm", id: SUB.address }, mandate: child(), ttl_seconds: 600, now: NOW })).rejects.toThrow(/does not allow delegation/);
    // A signature by another key than the delegator's is refused when assembling.
    const prepared = await d(child());
    await expect(assembleDelegation(issued, prepared, await SUB.signMessage({ message: prepared.text }), NOW)).rejects.toThrow(/BAD_SIGNATURE/);
  });
});

/* ---------------------------------------------------------------------------------------------------------------
 * Property tests. Seeded generator: every run is identical; a failure prints the seed and the case.
 * ------------------------------------------------------------------------------------------------------------- */
function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)]!;
  const some = <T>(xs: readonly T[]): T[] => xs.filter(() => next() < 0.5);
  return { int, pick, some, chance: (p: number) => next() < p };
}
type R = ReturnType<typeof rng>;
const ACTIONS = ["buy", "quote", "pay", "sign", "Pay", "x"] as const; // the last two are invalid
const CURRENCIES = ["BRL", "USD", "usd"] as const; // the last one is invalid
const AMOUNTS = [100, 500, 5000, 20000, 0, -1] as const; // the last two are invalid
const DAYS = ["2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z", "2027-02-01T00:00:00Z", "not a date"] as const;
const PARTIES = ["33000167000101", "beta.com.br", "*.beta.com.br", "gamma.io"] as const;

/** Well-formed terms; with `valid: false`, half of them get one field made invalid or removed. */
function randomTerms(r: R, opts: { complete?: boolean; valid?: boolean } = {}): Record<string, unknown> {
  const m = wellFormed(r);
  if (opts.valid !== false || r.chance(0.5)) return m;
  const field = r.pick(MANDATE_REQUIRED_FIELDS);
  if (!opts.complete && r.chance(0.3)) delete m[field];
  else m[field] = r.pick(INVALID[field]);
  return m;
}

const INVALID: Record<(typeof MANDATE_REQUIRED_FIELDS)[number], unknown[]> = {
  actions: [["Pay"], ["x"], "buy", [1]],
  max_per_operation: [{ amount: 0, currency: "BRL" }, { amount: -1, currency: "BRL" }, { amount: 10, currency: "brl" }, { amount: 10 }],
  max_per_day: [{ amount: 0, currency: "BRL" }, { amount: Number.POSITIVE_INFINITY, currency: "BRL" }, { amount: 10, currency: "BRL", extra: 1 }],
  currencies: [["usd"], "BRL", [""]],
  counterparties: [[""], "beta.com.br", ["x".repeat(129)]],
  payment_instruments: [[{ network: "visa", ref_sha256: "4111111111111111" }], [{ network: "pix" }], "pix"],
  valid_from: ["not a date", "2027-06-01T00:00:00Z"],
  valid_until: ["not a date", "2026-10-15T00:00:00Z", "2026-11-02T00:00:00Z"],
  delegation: [{ max_depth: 4, max_ttl_seconds: 600 }, { max_depth: 1, max_ttl_seconds: 10 }, { max_depth: 1 }, true]
};

function wellFormed(r: R): Record<string, unknown> {
  const ok = true;
  const amount = () => (ok ? r.pick(AMOUNTS.slice(0, 4)) : r.pick(AMOUNTS));
  const cur = () => (ok ? r.pick(CURRENCIES.slice(0, 2)) : r.pick(CURRENCIES));
  const actions = r.some(ok ? ACTIONS.slice(0, 4) : ACTIONS);
  const m: Record<string, unknown> = {
    actions: actions.length ? actions : ["buy"],
    max_per_operation: { amount: amount(), currency: cur() },
    max_per_day: { amount: amount() * 4, currency: cur() },
    currencies: [...new Set([cur(), cur()])],
    counterparties: r.some(PARTIES),
    payment_instruments: r.chance(0.3) ? [{ network: "pix", ref_sha256: "a".repeat(64) }] : [],
    valid_from: ok ? DAYS[r.int(2)] : r.pick(DAYS),
    valid_until: ok ? DAYS[3 + r.int(2)] : r.pick(DAYS),
    delegation: r.chance(0.5) ? null : { max_depth: 1 + r.int(ok ? 3 : 4), max_ttl_seconds: r.pick(ok ? [600, 3600] : [600, 3600, 10, 100000]) }
  };
  return m;
}

describe("issuance properties", () => {
  it("every credential issued from a valid input verifies; every input the verifier's schema refuses is refused at issuance", async () => {
    const SEED = 20261105;
    const r = rng(SEED);
    const k = await pki();
    let issuedCount = 0;
    let refused = 0;
    for (let i = 0; i < 160; i++) {
      const m = randomTerms(r, { valid: false });
      const where = `seed ${SEED}, case ${i}: ${JSON.stringify(m)}`;
      // What the verifier refuses: a mandate its schema refuses, or one already over at the issuance time.
      let schemaOk = true;
      try {
        const { delegation, ...rest } = m;
        const v = validateMandate(delegation === null ? rest : m);
        if (!v.valid_until || Date.parse(v.valid_until) <= NOW.getTime()) schemaOk = false;
      } catch {
        schemaOk = false;
      }
      let built;
      try {
        built = await buildMandate(input({ credential_id: `cred-${i}`, mandate: m as MandateTerms, ttl_seconds: r.pick([60, 86400, 90 * 86400]) }));
      } catch {
        refused++;
        continue;
      }
      expect(schemaOk, where).toBe(true); // accepted at issuance => the verifier's schema accepts it
      const { text } = await mandateSigningInput(built);
      const issued = await assembleCredential(built, await signerOf(k.company, k.root).sign(text), [], { anchors: k.anchors, now: NOW });
      const v = await verifySelfIssuedCredential({ ...issued, anchors: k.anchors, now: NOW });
      expect(failed(v), where).toEqual([]);
      issuedCount++;
    }
    expect(issuedCount).toBeGreaterThan(20); // both branches are exercised
    expect(refused).toBeGreaterThan(20);
  }, 60_000);

  it("delegation: issuance never accepts what verifyDelegationChain refuses, and refuses more only below the 60 s minimum lifetime", async () => {
    const SEED = 20261106;
    const r = rng(SEED);
    const { issued: base } = await issue();
    let accepted = 0;
    let refused = 0;
    let stricter = 0;
    for (let i = 0; i < 400; i++) {
      const parentTerms = randomTerms(r, { complete: true, valid: true });
      const parentMandate = (() => {
        const { delegation, ...rest } = parentTerms;
        return validateMandate(delegation === null ? rest : parentTerms);
      })();
      const credential = { ...base.credential, mandate: parentMandate };
      const childTerms = randomTerms(r, { complete: true, valid: true });
      if (r.chance(0.8)) Object.assign(childTerms, narrow(r, parentTerms)); // make a good share contained
      const ttl = r.pick([30, 600, 600, 3600, 7200]);
      const where = `seed ${SEED}, case ${i}: ${JSON.stringify({ parentTerms, childTerms, ttl })}`;

      // What a delegator could sign without the issuance checks, and what the verifier says about it.
      const { delegation, ...rest } = childTerms;
      const childMandate = validateMandate(delegation === null ? rest : childTerms);
      const expires = new Date(Math.min(NOW.getTime() + ttl * 1000, Date.parse(credential.expires_at))).toISOString();
      const raw = { version: 1 as const, credential_id: credential.credential_id, parent: null, delegate: { kind: "evm" as const, id: SUB.address }, depth: 1, issued_at: NOW.toISOString(), expires_at: expires, mandate: childMandate };
      const forged: Delegation = { ...raw, signature: await AGENT.signMessage({ message: await delegationText(raw) }) };
      const verified = (await verifyDelegationChain({ credential, chain: [forged], now: NOW })).ok;

      let built = true;
      try {
        await buildDelegation({ credential }, { delegate: { kind: "evm", id: SUB.address }, mandate: childTerms as MandateTerms, ttl_seconds: ttl, now: NOW });
      } catch {
        built = false;
      }
      // Never accepted at issuance and refused by the verifier.
      if (built) expect(verified, where).toBe(true);
      // The converse holds too, except for one gap of the existing code: prepareDelegation refuses a lifetime under
      // DELEGATION_MIN_TTL_SECONDS (60 s) and verifyDelegationChain does not check that minimum.
      if (verified && !built) {
        expect(ttl, where).toBeLessThan(60);
        stricter++;
      }
      if (built) accepted++;
      else refused++;
    }
    expect(accepted).toBeGreaterThan(40);
    expect(refused).toBeGreaterThan(40);
    expect(stricter).toBeGreaterThan(0); // the gap is real and exercised; see the PR
  }, 60_000);
});

/** Child terms derived from the parent's, sometimes widened by one step. */
function narrow(r: R, p: Record<string, unknown>): Record<string, unknown> {
  const c: Record<string, unknown> = {};
  const acts = r.some(p.actions as string[]);
  c.actions = acts.length ? acts : [(p.actions as string[])[0]];
  for (const k of ["max_per_operation", "max_per_day"]) {
    const m = p[k] as { amount: number; currency: string };
    c[k] = { amount: r.chance(0.85) ? m.amount : m.amount * 2, currency: m.currency };
  }
  c.currencies = p.currencies;
  c.counterparties = (p.counterparties as string[]).length ? p.counterparties : r.some(PARTIES);
  c.payment_instruments = p.payment_instruments;
  c.valid_from = p.valid_from;
  c.valid_until = p.valid_until;
  const d = p.delegation as { max_depth: number; max_ttl_seconds: number } | null;
  c.delegation = d && d.max_depth > 1 && r.chance(0.5) ? { max_depth: d.max_depth - 1, max_ttl_seconds: d.max_ttl_seconds } : null;
  return c;
}
