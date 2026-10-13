/// <reference types="node" /> // test-only: Buffer
import "reflect-metadata";
import { describe, expect, it } from "vitest";
import * as x509 from "@peculiar/x509";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { GeneralName, GeneralNames, OtherName, id_ce_subjectAltName } from "@peculiar/asn1-x509";
import { privateKeyToAccount } from "viem/accounts";
import { verifyMessage } from "viem";
import { generateAttestationKey, signAttestation, verifyIcpSignature } from "@kya-br/core";
import { KyaError, createKyaClient, revocationText, signChallengeWithEd25519, signChallengeWithEvmKey, signWithECnpj, toAnthropic, toLangChain, toOpenAI, toVercelAI, verifyAttestation } from "./index";

describe("client", () => {
  it("maps methods to routes, surfaces 402 and errors, routes paid calls through the internal channel when a key is given", async () => {
    const calls: { url: string; method: string; key: string | null; body: string | null }[] = [];
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method ?? "GET", key: new Headers(init?.headers).get("x-internal-key"), body: (init?.body as string) ?? null });
      if (url.endsWith("/allowed?action=pay&amount=80")) return new Response("{}", { status: 402 });
      if (url.includes("/v1/agents/nope")) return new Response(JSON.stringify({ error: "NOT_FOUND", message: "unknown" }), { status: 404 });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }) as unknown as typeof fetch;

    const kya = createKyaClient({ baseUrl: "https://x.test/", fetch: fetchImpl });
    expect(await kya.verify("abc")).toEqual({ ok: true });
    await kya.verifyByKey({ kind: "evm", id: "0xAb" });
    await kya.prove("abc", { challenge_id: "c", agent_signature: "s", ecnpj_signature: "e" });
    await expect(kya.allowed("abc", { action: "pay", amount: 80 })).rejects.toMatchObject({ code: "PAYMENT_REQUIRED", status: 402 });
    await expect(kya.verify("nope")).rejects.toMatchObject({ code: "NOT_FOUND", status: 404 });
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "GET https://x.test/v1/agents/abc",
      "GET https://x.test/v1/agents/by-key?kind=evm&id=0xAb",
      "POST https://x.test/v1/agents/abc/prove",
      "GET https://x.test/v1/agents/abc/allowed?action=pay&amount=80",
      "GET https://x.test/v1/agents/nope"
    ]);
    expect(JSON.parse(calls[2]!.body!)).toEqual({ challenge_id: "c", agent_signature: "s", ecnpj_signature: "e" });

    const internal = createKyaClient({ baseUrl: "https://x.test", fetch: fetchImpl, internalKey: "k" });
    await internal.register({ agent: { kind: "evm", id: "0xAb" }, cnpj: "11222333000181", mandate: { actions: ["pay"] } });
    expect(calls.at(-1)).toMatchObject({ url: "https://x.test/internal/v1/agents", method: "POST", key: "k" });
    await expect(internal.execute("nope", {})).rejects.toBeInstanceOf(KyaError);
  });

  it("exposes verifier tools for the frameworks", async () => {
    const kya = createKyaClient({ baseUrl: "https://x.test", fetch: (async () => new Response(JSON.stringify({ allowed: true }))) as unknown as typeof fetch });
    expect(toOpenAI(kya).map((t) => t.function.name)).toEqual(["kya_verify", "kya_check_action", "kya_verify_paid"]);
    expect(toAnthropic(kya)[1]!.input_schema.required).toEqual(["credential_id"]);
    const v = toVercelAI(kya, { tool: (d) => d, jsonSchema: (s) => s });
    expect(Object.keys(v)).toContain("kya_check_action");
    const lc = toLangChain(kya, (fn, def) => ({ fn, def }));
    expect(JSON.parse(await lc[1]!.fn({ credential_id: "abc", action: "pay" }))).toEqual({ allowed: true });
  });
});

describe("signing", () => {
  it("signs the challenge with an EVM key (EIP-191) and with an Ed25519 key", async () => {
    const pk = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;
    const text = "KYA Brasil: prove this agent key acts for a company\nchallenge: c1";
    const sig = await signChallengeWithEvmKey(pk, text);
    expect(await verifyMessage({ address: privateKeyToAccount(pk).address, message: text, signature: sig as `0x${string}` })).toBe(true);
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const raw = await signChallengeWithEd25519(kp.privateKey, text);
    expect(raw).toMatch(/^[A-Za-z0-9_-]+$/);
    const bytes = Uint8Array.from(atob(raw.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    expect(await crypto.subtle.verify({ name: "Ed25519" }, kp.publicKey, bytes, new TextEncoder().encode(text))).toBe(true);
  });

  it("produces a CMS the issuer accepts (throwaway ICP-Brasil-style PKI)", async () => {
    x509.cryptoProvider.set(globalThis.crypto as Crypto);
    const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
    const cnpj = "11222333000181";
    const caKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
    const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=AC Teste, O=ICP-Brasil, C=BR", notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), signingAlgorithm: alg, keys: caKeys, extensions: [new x509.BasicConstraintsExtension(true, 1, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true)] });
    const leafKeys = (await crypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
    const other = new OtherName({ typeId: "2.16.76.1.3.3", value: AsnConvert.serialize(new OctetString(new TextEncoder().encode(cnpj))) });
    const san = new x509.Extension(id_ce_subjectAltName, false, AsnConvert.serialize(new GeneralNames([new GeneralName({ otherName: other })])));
    const leaf = await x509.X509CertificateGenerator.create({ serialNumber: "02", subject: `CN=ACME LTDA:${cnpj}, O=ICP-Brasil, C=BR`, issuer: ca.subject, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01"), signingAlgorithm: alg, publicKey: leafKeys.publicKey, signingKey: caKeys.privateKey, extensions: [san] });
    const pkcs8 = Buffer.from(await crypto.subtle.exportKey("pkcs8", leafKeys.privateKey)).toString("base64");
    const text = "KYA Brasil: prove this agent key acts for a company\nchallenge: c2";
    const cms = await signWithECnpj({ certificatePem: leaf.toString("pem"), privateKeyPem: `-----BEGIN PRIVATE KEY-----\n${pkcs8}\n-----END PRIVATE KEY-----`, chainPem: [ca.toString("pem")] }, text);
    const proof = await verifyIcpSignature({ cmsBase64: cms, challenge: text, expectedCnpj: cnpj, anchors: [Buffer.from(ca.rawData).toString("base64")], now: new Date("2026-10-12T00:00:00Z") });
    expect(proof.cnpj).toBe(cnpj);
    expect(revocationText("abc", "n1")).toBe("KYA Brasil: revoke abc\nn1");
  });
});

describe("attestation", () => {
  it("verifies a credential signed by the issuer and rejects a modified one", async () => {
    const k = await generateAttestationKey();
    const priv = await crypto.subtle.importKey("pkcs8", Buffer.from(k.privateKeyPkcs8, "base64"), { name: "Ed25519" }, false, ["sign"]);
    const credential: Record<string, unknown> = { credential_id: "abc", status: "active", mandate: { actions: ["pay"] } };
    credential.attestation = await signAttestation(credential, priv, k.keyId, "https://x.test/v1/verify");
    expect(await verifyAttestation(credential, { publicJwk: k.publicJwk })).toMatchObject({ valid: true, key_id: k.keyId });
    expect(await verifyAttestation({ ...credential, status: "revoked" }, { publicJwk: k.publicJwk })).toMatchObject({ valid: false });
    const fetchImpl = (async () => new Response(JSON.stringify({ keys: [{ key_id: k.keyId, jwk: k.publicJwk }] }))) as unknown as typeof fetch;
    expect((await verifyAttestation(credential, { baseUrl: "https://x.test", fetch: fetchImpl })).valid).toBe(true);
  });
});
