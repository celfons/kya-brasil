/// <reference types="node" /> // test-only: node:sqlite, node:fs
import { register, prove } from "./service"; // loads reflect-metadata (via core) before x509
import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as x509 from "@peculiar/x509";
import { privateKeyToAccount } from "viem/accounts";
import { buildDetachedCms, generateAttestationKey } from "@kya-brasil/core";
import { resetAnchorsCache } from "./anchors";
import { resetCrlMemory } from "./revocation";
import type { AppEnv } from "./env";

x509.cryptoProvider.set(globalThis.crypto as Crypto);
const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
/** subjectAltName with the ICP-Brasil CNPJ otherName (2.16.76.1.3.3) as an OCTET STRING, DER by hand. */
const sanWithCnpj = (cnpj: string) => {
  const value = [0x04, cnpj.length, ...new TextEncoder().encode(cnpj)];
  const explicit = [0xa0, value.length, ...value];
  const other = [0x06, 0x05, 0x60, 0x4c, 0x01, 0x03, 0x03, ...explicit];
  const name = [0xa0, other.length, ...other];
  return new x509.Extension("2.5.29.17", false, new Uint8Array([0x30, name.length, ...name]));
};
const CNPJ = "11222333000181";
const CRL_URL = "http://crl.test/ac.crl";
const AGENT = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

/** A D1 stand-in over node:sqlite with the worker's migrations applied. */
function d1(): D1Database {
  const db = new DatabaseSync(":memory:");
  const dir = new URL("../migrations/", import.meta.url);
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".sql")).sort()) db.exec(readFileSync(new URL(f, dir), "utf8"));
  const stmt = (sql: string, args: unknown[] = []) => ({
    bind: (...a: unknown[]) => stmt(sql, a),
    first: async () => (db.prepare(sql).get(...(args as never[])) as unknown) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...(args as never[])) }),
    run: async () => {
      const r = db.prepare(sql).run(...(args as never[]));
      return { success: true, meta: { changes: Number(r.changes) } };
    }
  });
  return { prepare: (sql: string) => stmt(sql), batch: async (list: { run: () => Promise<unknown> }[]) => Promise.all(list.map((s) => s.run())) } as unknown as D1Database;
}

function kv(): KVNamespace {
  const m = new Map<string, string>();
  return { get: async (k: string, t?: string) => (m.has(k) ? (t === "json" ? JSON.parse(m.get(k)!) : m.get(k)) : null), put: async (k: string, v: string) => void m.set(k, v), delete: async (k: string) => void m.delete(k) } as unknown as KVNamespace;
}

async function pki() {
  const caKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste ICP-Brasil, O=ICP-Brasil, C=BR", notBefore: new Date(Date.now() - 86400_000), notAfter: new Date(Date.now() + 365 * 86400_000), signingAlgorithm: alg, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)] });
  const leafKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const san = sanWithCnpj(CNPJ);
  const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "02", subject: `CN=ACME LTDA:${CNPJ}, O=ICP-Brasil, C=BR`, issuer: ca.subject, notBefore: new Date(Date.now() - 86400_000), notAfter: new Date(Date.now() + 365 * 86400_000), signingAlgorithm: alg, publicKey: leafKeys.publicKey, signingKey: caKeys.privateKey, extensions: [san, new x509.CRLDistributionPointsExtension([CRL_URL]), new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.nonRepudiation, true)] });
  const crl = await x509.X509CrlGenerator.create({ issuer: ca.subject, thisUpdate: new Date(Date.now() - 3600_000), nextUpdate: new Date(Date.now() + 86400_000), signingAlgorithm: alg, signingKey: caKeys.privateKey, entries: [] });
  return { ca, leaf, leafKeys, crl: crl.rawData };
}

async function ecnpjSign(p: Awaited<ReturnType<typeof pki>>, text: string): Promise<string> {
  const sign = async (data: Uint8Array) => new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", p.leafKeys.privateKey, data as BufferSource));
  return buildDetachedCms({ text, certificates: [new Uint8Array(p.leaf.rawData), new Uint8Array(p.ca.rawData)], sign });
}

describe("the mandate issued is the one the certificate holder was shown", () => {
  let env: AppEnv;
  let p: Awaited<ReturnType<typeof pki>>;
  const ORIGIN = "https://kya.test";
  const small = { actions: ["quote"], max_per_operation: { amount: 100, currency: "BRL" } };
  const large = { actions: ["quote", "order", "pay"], max_per_operation: { amount: 1_000_000, currency: "BRL" } };

  beforeEach(async () => {
    p = await pki();
    resetAnchorsCache();
    resetCrlMemory();
    vi.stubGlobal("fetch", async (url: string) => (url === CRL_URL ? new Response(p.crl) : new Response("no network in tests", { status: 503 })));
    env = { DB: d1(), CACHE: kv(), REGISTRATION_CHECK: "off", ATTEST_PRIVATE_KEY: (await generateAttestationKey()).privateKeyPkcs8, ICP_ANCHORS_PEM: p.ca.toString("pem") } as unknown as AppEnv;
  });
  afterEach(() => vi.unstubAllGlobals());

  const signBoth = async (text: string) => ({ agent_signature: await AGENT.signMessage({ message: text }), ecnpj_signature: await ecnpjSign(p, text) });

  it("issues the mandate that was requested with the signed challenge", async () => {
    const r = await register(env, ORIGIN, { agent: { kind: "evm", id: AGENT.address }, cnpj: CNPJ, mandate: small });
    const issued = await prove(env, ORIGIN, r.credential_id, { challenge_id: r.challenge.id, ...(await signBoth(r.challenge.text)) });
    expect(issued.credential.mandate).toEqual(small);
  });

  it("a second registration cannot swap the mandate under a challenge already handed to the holder", async () => {
    const first = await register(env, ORIGIN, { agent: { kind: "evm", id: AGENT.address }, cnpj: CNPJ, mandate: small });
    // The holder opens the link for `small`; meanwhile whoever holds the agent key registers again with `large`.
    const second = await register(env, ORIGIN, { agent: { kind: "evm", id: AGENT.address }, cnpj: CNPJ, mandate: large });
    expect(second.credential_id).toBe(first.credential_id);
    // The holder signs the first challenge (the one shown with `small`): it no longer issues anything.
    await expect(prove(env, ORIGIN, first.credential_id, { challenge_id: first.challenge.id, ...(await signBoth(first.challenge.text)) })).rejects.toThrow(/challenge/);
    // The second challenge issues `large`, which is what its link shows.
    const issued = await prove(env, ORIGIN, second.credential_id, { challenge_id: second.challenge.id, ...(await signBoth(second.challenge.text)) });
    expect(issued.credential.mandate).toEqual(large);
  });

  it("issues the challenge's mandate even if the pending row changed underneath", async () => {
    const r = await register(env, ORIGIN, { agent: { kind: "evm", id: AGENT.address }, cnpj: CNPJ, mandate: small });
    await env.DB.prepare("UPDATE agents SET mandate = ?2 WHERE id = ?1").bind(r.credential_id, JSON.stringify(large)).run();
    const issued = await prove(env, ORIGIN, r.credential_id, { challenge_id: r.challenge.id, ...(await signBoth(r.challenge.text)) });
    expect(issued.credential.mandate).toEqual(small);
  });
});
