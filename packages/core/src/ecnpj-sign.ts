/**
 * Signing with the company's e-CNPJ, for whoever holds it (D-26, D-27). One CMS builder for every kind of
 * certificate: the caller gives the certificate chain and a function that signs bytes with the private key.
 *   A1 (.pfx / .p12 file): openPfx / signWithECnpjPfx here (node-forge reads the legacy 3DES/RC2 PKCS#12
 *     many Brazilian A1 files use; the key is then used through Web Crypto);
 *   A3 (token, smart card), HSM, cloud certificate: anything that can produce an RSA PKCS#1 v1.5 SHA-256
 *     signature (PKCS#11 C_Sign with CKM_SHA256_RSA_PKCS, a cloud signing API, ...) plugs into
 *     buildDetachedCms. The kya-sign command in @kya-brasil/agent-tools does it for PKCS#11 tokens.
 * Pure: no storage, no network. The issuer never receives the certificate or its password.
 */
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import forge from "node-forge";
import { KyaError } from "./types.js";

const OID_DATA = "1.2.840.113549.1.7.1";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_SHA256_RSA = "1.2.840.113549.1.1.11";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_SIGNING_TIME = "1.2.840.113549.1.9.5";

/** Signs `data` with the certificate's RSA private key: PKCS#1 v1.5 over SHA-256 (the signer hashes). */
export type RawSigner = (data: Uint8Array) => Promise<Uint8Array>;

const toArrayBuffer = (u: Uint8Array) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

function ensureEngine() {
  pkijs.setEngine("kya-sign", new pkijs.CryptoEngine({ name: "kya-sign", crypto: globalThis.crypto as Crypto }));
}

/**
 * Detached CMS/PKCS#7 SignedData (base64 DER) over `text`, with signed attributes (content type, message
 * digest, signing time) and the given certificates (signer first, then its chain, DER). The issuer accepts it as
 * `ecnpj_signature`.
 */
export async function buildDetachedCms(p: { text: string; certificates: Uint8Array[]; sign: RawSigner; signingTime?: Date }): Promise<string> {
  ensureEngine();
  if (!p.certificates.length) throw new KyaError("INVALID_INPUT", "no signer certificate");
  const certs = p.certificates.map((der) => pkijs.Certificate.fromBER(toArrayBuffer(der)));
  const leaf = certs[0]!;
  const content = new TextEncoder().encode(p.text);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", content));
  const signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new pkijs.Attribute({ type: OID_CONTENT_TYPE, values: [new asn1js.ObjectIdentifier({ value: OID_DATA })] }),
      new pkijs.Attribute({ type: OID_MESSAGE_DIGEST, values: [new asn1js.OctetString({ valueHex: toArrayBuffer(digest) })] }),
      new pkijs.Attribute({ type: OID_SIGNING_TIME, values: [new asn1js.UTCTime({ valueDate: p.signingTime ?? new Date() })] })
    ]
  });
  // What is signed is the DER of the attributes as a SET (tag 0x31), not the [0] IMPLICIT form they travel in.
  const toBeSigned = new Uint8Array(signedAttrs.toSchema().toBER(false));
  toBeSigned[0] = 0x31;
  const signature = await p.sign(toBeSigned);
  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({ issuer: leaf.issuer, serialNumber: leaf.serialNumber }),
    digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 }),
    signedAttrs,
    signatureAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256_RSA }),
    signature: new asn1js.OctetString({ valueHex: toArrayBuffer(signature) })
  });
  const signed = new pkijs.SignedData({
    version: 1,
    digestAlgorithms: [new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 })],
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: OID_DATA }),
    certificates: certs,
    signerInfos: [signerInfo]
  });
  const ci = new pkijs.ContentInfo({ contentType: OID_SIGNED_DATA, content: signed.toSchema(true) });
  const der = new Uint8Array(ci.toSchema().toBER(false));
  let bin = "";
  for (const b of der) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** What a certificate holder exposes to sign: subject, CNPJ, validity, chain and the sign step. */
export interface ECnpjSigner {
  /** Subject of the e-CNPJ certificate, e.g. "CN=ACME LTDA:11222333000181, ...". */
  subject: string;
  /** CNPJ read from the certificate's common name ("NAME:CNPJ"), when present. */
  cnpj: string | null;
  notAfter: Date;
  /** Signer certificate first, then the chain found with it (DER). */
  certificates: Uint8Array[];
  /** Detached CMS (base64 DER) over `text`; refuses a text whose "cnpj:" line names another company. */
  sign(text: string): Promise<string>;
}

/** CNPJ in a common name ending in ":<14 digits>", the ICP-Brasil convention for e-CNPJ. */
export const cnpjFromCommonName = (cn: string) => /:(\d{14})\s*$/.exec(cn)?.[1] ?? null;

/** Wraps a raw signer and its certificates into an ECnpjSigner (used for A1 files, tokens, HSMs, cloud). */
export function ecnpjSigner(p: { certificates: Uint8Array[]; sign: RawSigner }): ECnpjSigner {
  const leaf = forge.pki.certificateFromAsn1(forge.asn1.fromDer(forge.util.binary.raw.encode(p.certificates[0]!)));
  const cn = String(leaf.subject.getField("CN")?.value ?? "");
  const cnpj = cnpjFromCommonName(cn);
  return {
    subject: leaf.subject.attributes.map((a: forge.pki.CertificateField) => `${a.shortName ?? a.name}=${a.value}`).join(", "),
    cnpj,
    notAfter: leaf.validity.notAfter,
    certificates: p.certificates,
    async sign(text: string) {
      const asked = /^cnpj: (\d{14})$/m.exec(text)?.[1];
      if (asked && cnpj && asked !== cnpj) throw new KyaError("CNPJ_MISMATCH", `this certificate is for CNPJ ${cnpj}, the text is for ${asked}`);
      return buildDetachedCms({ text, certificates: p.certificates, sign: p.sign });
    }
  };
}

const certDer = (c: forge.pki.Certificate) => new Uint8Array(forge.util.binary.raw.decode(forge.asn1.toDer(forge.pki.certificateToAsn1(c)).getBytes()));

/** Opens an A1 e-CNPJ file (.pfx / .p12 bytes) with its password. The key stays in memory, inside Web Crypto. */
export async function openPfx(pfx: Uint8Array, password: string): Promise<ECnpjSigner> {
  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.binary.raw.encode(pfx)), false, password);
  } catch (e) {
    throw new KyaError("INVALID_INPUT", `could not open the certificate file (wrong password or not a .pfx/.p12): ${(e as Error).message}`);
  }
  const oids = forge.pki.oids;
  const keyBag = [oids.pkcs8ShroudedKeyBag!, oids.keyBag!].flatMap((t) => p12.getBags({ bagType: t })[t] ?? []).find((b) => b.key);
  if (!keyBag?.key) throw new KyaError("INVALID_INPUT", "the certificate file has no private key");
  const key = keyBag.key as forge.pki.rsa.PrivateKey;
  const certs = (p12.getBags({ bagType: oids.certBag! })[oids.certBag!] ?? []).map((b: forge.pkcs12.Bag) => b.cert).filter((c): c is forge.pki.Certificate => !!c);
  // The signer is the certificate whose public key matches the private key; the others are its chain.
  const leaf = certs.find((c: forge.pki.Certificate) => (c.publicKey as forge.pki.rsa.PublicKey).n?.equals(key.n));
  if (!leaf) throw new KyaError("INVALID_INPUT", "no certificate in the file matches its private key");
  const pkcs8 = forge.util.binary.raw.decode(forge.asn1.toDer(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(key))).getBytes());
  const cryptoKey = await crypto.subtle.importKey("pkcs8", toArrayBuffer(pkcs8), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  return ecnpjSigner({
    certificates: [leaf, ...certs.filter((c) => c !== leaf)].map(certDer),
    sign: async (data) => new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, cryptoKey, toArrayBuffer(data)))
  });
}

/** One call: sign `text` with the e-CNPJ in an A1 file. Returns the base64 DER the issuer expects as ecnpj_signature. */
export async function signWithECnpjPfx(pfx: Uint8Array, password: string, text: string): Promise<string> {
  return (await openPfx(pfx, password)).sign(text);
}

/**
 * Link to an issuer's signing page (<issuer>/sign) for the person who holds the company's e-CNPJ. The agent
 * registers, signs its half and sends this link; the person sees what they authorize and signs in the browser.
 */
export function signingLink(p: { issuer: string; credentialId: string; challenge: { id: string; text: string }; agentSignature?: string }): string {
  const u = new URL("/sign", p.issuer);
  u.searchParams.set("id", p.credentialId);
  u.searchParams.set("challenge_id", p.challenge.id);
  let bin = "";
  for (const b of new TextEncoder().encode(p.challenge.text)) bin += String.fromCharCode(b);
  u.searchParams.set("text", btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
  if (p.agentSignature) u.searchParams.set("agent_signature", p.agentSignature);
  return u.toString();
}

/** The challenge text carried by a signing link (inverse of signingLink), with its ids. */
export function readSigningLink(link: string): { issuer: string; credentialId: string | null; challengeId: string | null; agentSignature: string | null; text: string } {
  const u = new URL(link);
  const t = u.searchParams.get("text");
  if (!t) throw new KyaError("INVALID_INPUT", "the signing link has no text");
  const bin = atob(t.replace(/-/g, "+").replace(/_/g, "/"));
  return {
    issuer: u.origin,
    credentialId: u.searchParams.get("id"),
    challengeId: u.searchParams.get("challenge_id"),
    agentSignature: u.searchParams.get("agent_signature"),
    text: new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)))
  };
}
