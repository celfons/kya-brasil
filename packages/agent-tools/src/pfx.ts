/**
 * e-CNPJ signing straight from the .pfx / .p12 file companies actually have (A1 certificates). node-forge reads
 * the legacy PKCS#12 encryptions (3DES, RC2) that Web Crypto cannot, which many Brazilian A1 files still use.
 * The page at <issuer>/sign runs the same steps in the browser; keep the two in sync.
 */
import forge from "node-forge";

export interface PfxSigner {
  /** Subject of the e-CNPJ certificate, e.g. "CN=ACME LTDA:11222333000181, ...". */
  subject: string;
  /** CNPJ read from the certificate's common name ("NAME:CNPJ"), when present. */
  cnpj: string | null;
  notAfter: Date;
  /** Detached CMS/PKCS#7 SignedData (base64 DER) over `text`, with the certificate chain found in the file. */
  sign(text: string): string;
}

const OID = {
  shroudedKeyBag: forge.pki.oids.pkcs8ShroudedKeyBag!,
  keyBag: forge.pki.oids.keyBag!,
  certBag: forge.pki.oids.certBag!,
  sha256: forge.pki.oids.sha256!,
  contentType: forge.pki.oids.contentType!,
  data: forge.pki.oids.data!,
  messageDigest: forge.pki.oids.messageDigest!,
  signingTime: forge.pki.oids.signingTime!
};

const cnOf = (c: forge.pki.Certificate) => String(c.subject.getField("CN")?.value ?? "");
const cnpjOfCn = (cn: string) => /:(\d{14})\s*$/.exec(cn)?.[1] ?? null;

/** Opens a PKCS#12 file (bytes) with its password; throws a readable error on a wrong password or an empty file. */
export function openPfx(pfx: Uint8Array, password: string): PfxSigner {
  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(forge.util.binary.raw.encode(pfx)), false, password);
  } catch (e) {
    throw new Error(`could not open the certificate file (wrong password or not a .pfx/.p12): ${(e as Error).message}`);
  }
  const keyBag = [OID.shroudedKeyBag, OID.keyBag].flatMap((t) => p12.getBags({ bagType: t })[t] ?? []).find((b) => b.key);
  if (!keyBag?.key) throw new Error("the file has no private key");
  const key = keyBag.key as forge.pki.rsa.PrivateKey;
  const certs = (p12.getBags({ bagType: OID.certBag })[OID.certBag] ?? []).map((b: forge.pkcs12.Bag) => b.cert).filter((c): c is forge.pki.Certificate => !!c);
  // The signer is the certificate whose public key matches the private key; the others are its chain.
  const leaf = certs.find((c: forge.pki.Certificate) => (c.publicKey as forge.pki.rsa.PublicKey).n?.equals(key.n));
  if (!leaf) throw new Error("no certificate in the file matches its private key");
  return {
    subject: leaf.subject.attributes.map((a: forge.pki.CertificateField) => `${a.shortName ?? a.name}=${a.value}`).join(", "),
    cnpj: cnpjOfCn(cnOf(leaf)),
    notAfter: leaf.validity.notAfter,
    sign(text: string) {
      const p7 = forge.pkcs7.createSignedData();
      p7.content = forge.util.createBuffer(forge.util.encodeUtf8(text));
      p7.addCertificate(leaf);
      for (const c of certs) if (c !== leaf) p7.addCertificate(c);
      p7.addSigner({
        key,
        certificate: leaf,
        digestAlgorithm: OID.sha256,
        authenticatedAttributes: [
          { type: OID.contentType, value: OID.data },
          { type: OID.messageDigest },
          { type: OID.signingTime, value: new Date() as unknown as string }
        ]
      });
      p7.sign({ detached: true });
      return forge.util.encode64(forge.asn1.toDer(p7.toAsn1()).getBytes());
    }
  };
}

/** One call: sign `text` with the e-CNPJ in a .pfx/.p12 file. Returns the base64 DER the issuer expects as ecnpj_signature. */
export function signWithECnpjPfx(pfx: Uint8Array, password: string, text: string): string {
  return openPfx(pfx, password).sign(text);
}
