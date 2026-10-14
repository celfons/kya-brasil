/**
 * A3 e-CNPJ (token or smart card) through PKCS#11, the interface every ICP-Brasil token driver ships
 * (e.g. SafeNet eToken: libeTPkcs11.so / eTPKCS11.dll; GD/Watchdata/Oberthur: their own libraries). The
 * private key never leaves the device: only the bytes to sign go in and the signature comes out. Node only;
 * needs the optional package pkcs11js (npm install pkcs11js) and the vendor's library path.
 */
import { ecnpjSigner, type ECnpjSigner } from "@kya-brasil/core";

export interface TokenOptions {
  /** Path to the vendor's PKCS#11 library (.so / .dylib / .dll). */
  library: string;
  /** The token's user PIN. */
  pin: string;
  /** Index among the slots with a token present (default 0). */
  slot?: number;
  /** Pick the certificate by its label on the token; default: the one whose common name carries a CNPJ. */
  label?: string;
}

export interface TokenCertificate {
  label: string;
  subject: string;
  cnpj: string | null;
  notAfter: Date;
}

// DigestInfo prefix for SHA-256 (RFC 8017), for tokens that only offer raw CKM_RSA_PKCS.
const SHA256_DIGEST_INFO = Uint8Array.from([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]);

type P11 = typeof import("pkcs11js");

async function load(): Promise<P11> {
  try {
    const mod = (await import("pkcs11js")) as P11 & { default?: P11 };
    return mod.default ?? mod;
  } catch {
    throw new Error("A3 tokens need the optional package pkcs11js: npm install pkcs11js");
  }
}

interface Session {
  p11: P11;
  lib: InstanceType<P11["PKCS11"]>;
  session: Buffer;
  certs: { handle: Buffer; der: Uint8Array; id: Buffer; label: string; signer: ECnpjSigner | null }[];
  close(): void;
}

async function openSession(o: { library: string; pin?: string; slot?: number }): Promise<Session> {
  const p11 = await load();
  const lib = new p11.PKCS11();
  lib.load(o.library);
  lib.C_Initialize();
  const finalize = () => {
    try {
      lib.C_Finalize();
    } catch {
      /* already finalized */
    }
  };
  try {
    const slots = lib.C_GetSlotList(true);
    const slot = slots[o.slot ?? 0];
    if (!slot) throw new Error(slots.length ? `no token in slot ${o.slot}` : "no token found: is it plugged in, and is this the right library?");
    const session = lib.C_OpenSession(slot, p11.CKF_SERIAL_SESSION);
    if (o.pin !== undefined) lib.C_Login(session, p11.CKU_USER, o.pin);
    lib.C_FindObjectsInit(session, [{ type: p11.CKA_CLASS, value: p11.CKO_CERTIFICATE }]);
    const handles = lib.C_FindObjects(session, 64);
    lib.C_FindObjectsFinal(session);
    const certs = handles.map((handle) => {
      const [value, id, label] = lib.C_GetAttributeValue(session, handle, [{ type: p11.CKA_VALUE }, { type: p11.CKA_ID }, { type: p11.CKA_LABEL }]);
      const der = new Uint8Array(value!.value as Buffer);
      let signer: ECnpjSigner | null = null;
      try {
        signer = ecnpjSigner({ certificates: [der], sign: async () => new Uint8Array() });
      } catch {
        /* not an X.509 certificate we can read */
      }
      return { handle, der, id: (id!.value as Buffer) ?? Buffer.alloc(0), label: (label!.value as Buffer)?.toString("utf8") ?? "", signer };
    });
    return {
      p11,
      lib,
      session,
      certs,
      close() {
        try {
          if (o.pin !== undefined) lib.C_Logout(session);
          lib.C_CloseSession(session);
        } catch {
          /* ignore */
        }
        finalize();
      }
    };
  } catch (e) {
    finalize();
    throw e;
  }
}

/** Certificates on the token (no PIN needed on most tokens), to pick one with `label`. */
export async function listTokenCertificates(o: { library: string; slot?: number; pin?: string }): Promise<TokenCertificate[]> {
  const s = await openSession(o);
  try {
    return s.certs.filter((c) => c.signer).map((c) => ({ label: c.label, subject: c.signer!.subject, cnpj: c.signer!.cnpj, notAfter: c.signer!.notAfter }));
  } finally {
    s.close();
  }
}

/**
 * Opens the token and returns an e-CNPJ signer (same interface as openPfx). Call close() when done; it logs out
 * and releases the token.
 */
export async function openToken(o: TokenOptions): Promise<ECnpjSigner & { close(): void }> {
  const s = await openSession(o);
  try {
    const { p11, lib, session } = s;
    const cert = o.label ? s.certs.find((c) => c.label === o.label) : s.certs.find((c) => c.signer?.cnpj);
    if (!cert?.signer) throw new Error(o.label ? `no certificate labelled "${o.label}" on the token` : "no e-CNPJ certificate on the token (none with a CNPJ in its name); pass a label");
    lib.C_FindObjectsInit(session, [{ type: p11.CKA_CLASS, value: p11.CKO_PRIVATE_KEY }, { type: p11.CKA_ID, value: cert.id }]);
    const [key] = lib.C_FindObjects(session, 1);
    lib.C_FindObjectsFinal(session);
    if (!key) throw new Error("the token has no private key for that certificate (wrong PIN or key not on this token)");
    // The chain: the other certificates on the token, when any (the issuer also has the ICP-Brasil bundle).
    const chain = s.certs.filter((c) => c !== cert && c.signer).map((c) => c.der);
    const signRaw = async (data: Uint8Array): Promise<Uint8Array> => {
      try {
        lib.C_SignInit(session, { mechanism: p11.CKM_SHA256_RSA_PKCS }, key);
        return new Uint8Array(lib.C_Sign(session, Buffer.from(data), Buffer.alloc(1024)));
      } catch {
        // Older tokens: hash here and sign the DigestInfo with raw PKCS#1 v1.5.
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>));
        lib.C_SignInit(session, { mechanism: p11.CKM_RSA_PKCS }, key);
        return new Uint8Array(lib.C_Sign(session, Buffer.concat([SHA256_DIGEST_INFO, digest]), Buffer.alloc(1024)));
      }
    };
    return { ...ecnpjSigner({ certificates: [cert.der, ...chain], sign: signRaw }), close: () => s.close() };
  } catch (e) {
    s.close();
    throw e;
  }
}
