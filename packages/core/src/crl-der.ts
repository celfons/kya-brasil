/**
 * A bounded, streaming DER reader for X.509 CRLs (RFC 5280, section 5.1), so that real ICP-Brasil CRLs with tens or
 * hundreds of thousands of entries (AC SERPRO RFB v5: ~77 000, ~3.7 MB) can be verified. @peculiar/x509's X509Crl
 * decodes through asn1js, whose default limit of 10 000 ASN.1 nodes refuses any CRL above about 1 240 entries.
 *
 *   CertificateList ::= SEQUENCE { tbsCertList TBSCertList, signatureAlgorithm AlgorithmIdentifier, signatureValue BIT STRING }
 *   TBSCertList ::= SEQUENCE { version INTEGER OPTIONAL, signature AlgorithmIdentifier, issuer Name, thisUpdate Time,
 *     nextUpdate Time OPTIONAL, revokedCertificates SEQUENCE OF SEQUENCE { userCertificate INTEGER, revocationDate Time,
 *     crlEntryExtensions Extensions OPTIONAL } OPTIONAL, crlExtensions [0] EXPLICIT Extensions OPTIONAL }
 *
 * Entries are indexed by serial number with only their offsets; their extensions are decoded on lookup. Bounds:
 * MAX_CRL_BYTES of input and MAX_CRL_ENTRIES entries, so a hostile CRL cannot exhaust memory.
 */

/** Largest DER CRL accepted (64 MiB, ~17x the largest ICP-Brasil CRL seen). */
export const MAX_CRL_BYTES = 64 * 1024 * 1024;
/** Most revoked entries accepted in one CRL (about 1.4 million fit in 64 MiB; ICP-Brasil's largest has ~77 000). */
export const MAX_CRL_ENTRIES = 2_000_000;

export class DerError extends Error {}

interface Tlv { tag: number; pos: number; start: number; end: number }

function readTlv(b: Uint8Array, pos: number, limit: number): Tlv {
  if (pos + 2 > limit) throw new DerError(`truncated TLV at ${pos}`);
  const tag = b[pos]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError(`multi-byte tag at ${pos}`);
  let len = b[pos + 1]!;
  let start = pos + 2;
  if (len === 0x80) throw new DerError(`indefinite length at ${pos} (not DER)`);
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n > 4) throw new DerError(`length too long at ${pos}`);
    if (start + n > limit) throw new DerError(`truncated length at ${pos}`);
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[start + i]!;
    start += n;
  }
  const end = start + len;
  if (end > limit) throw new DerError(`value overruns its container at ${pos}`);
  return { tag, pos, start, end };
}

function children(b: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let p = parent.start; p < parent.end; ) {
    const t = readTlv(b, p, parent.end);
    out.push(t);
    p = t.end;
  }
  return out;
}

const isTime = (t: Tlv | undefined): t is Tlv => !!t && (t.tag === 0x17 || t.tag === 0x18);
const hexOf = (u: Uint8Array) => {
  let s = "";
  for (const x of u) s += x.toString(16).padStart(2, "0");
  return s;
};

function readTime(b: Uint8Array, t: Tlv): Date {
  const s = String.fromCodePoint(...b.subarray(t.start, t.end));
  let m: RegExpExecArray | null;
  let iso: string | null = null;
  if (t.tag === 0x17 && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) {
    const yy = Number(m[1]);
    iso = `${yy >= 50 ? 1900 + yy : 2000 + yy}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
  } else if (t.tag === 0x18 && (m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(s))) {
    iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ""}Z`;
  }
  const d = iso ? new Date(iso) : null;
  if (!d || Number.isNaN(d.getTime())) throw new DerError(`not a DER time: "${s}"`);
  return d;
}

/** Appends one decoded OID arc; the first one encodes the first two arcs (X.690 8.19.4). */
function pushArc(parts: number[], v: number): void {
  if (parts.length) parts.push(v);
  else if (v < 80) parts.push(Math.floor(v / 40), v % 40);
  else parts.push(2, v - 80);
}

/** Dotted OID of an OBJECT IDENTIFIER TLV. */
function readOid(b: Uint8Array, t: Tlv): string {
  if (t.tag !== 0x06) throw new DerError(`expected OBJECT IDENTIFIER at ${t.pos}`);
  const parts: number[] = [];
  let v = 0;
  for (let i = t.start; i < t.end; i++) {
    v = v * 128 + (b[i]! & 0x7f);
    if ((b[i]! & 0x80) === 0) {
      pushArc(parts, v);
      v = 0;
    }
  }
  return parts.join(".");
}

export interface CrlEntryInfo {
  revocationDate: Date;
  /** RFC 5280 reasonCode (2.5.29.21), when present. */
  reason?: number;
  /** RFC 5280 invalidityDate (2.5.29.24), when present. */
  invalidity?: Date;
}

export interface ParsedCrl {
  /** DER of the issuer Name. */
  issuerDer: Uint8Array;
  thisUpdate: Date;
  nextUpdate: Date | null;
  /** DER of TBSCertList: the bytes the signature covers. */
  tbs: Uint8Array;
  /** Outer signatureAlgorithm OID and its DER parameters (if any). */
  signatureAlgorithm: string;
  signatureAlgorithmParams: Uint8Array | null;
  signature: Uint8Array;
  entryCount: number;
  /** Looks a serial up (lowercase hex, no leading zeros). */
  entry(serial: string): CrlEntryInfo | null;
}

interface Envelope { tbsT: Tlv; algT: Tlv; sigT: Tlv }

/** CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }, spanning the whole input. */
function readEnvelope(b: Uint8Array): Envelope {
  if (b.length > MAX_CRL_BYTES) throw new DerError(`CRL larger than ${MAX_CRL_BYTES} bytes`);
  const outer = readTlv(b, 0, b.length);
  if (outer.tag !== 0x30 || outer.end !== b.length) throw new DerError("not a DER SEQUENCE spanning the input");
  const top = children(b, outer);
  const [tbsT, algT, sigT] = top;
  if (top.length !== 3 || tbsT?.tag !== 0x30 || algT?.tag !== 0x30 || sigT?.tag !== 0x03) throw new DerError("not a CertificateList");
  return { tbsT, algT, sigT };
}

interface TbsHeader { issuer: Tlv; thisT: Tlv; nextT: Tlv | null; list: Tlv | null }

/** The TBSCertList fields; checks the inner signature algorithm equals the outer one (RFC 5280 5.1.1.2). */
function readTbsHeader(b: Uint8Array, tbsT: Tlv, algT: Tlv): TbsHeader {
  const f = children(b, tbsT);
  let i = 0;
  if (f[i]?.tag === 0x02) i++; // version
  const innerAlg = f[i++];
  if (innerAlg?.tag !== 0x30) throw new DerError("missing TBSCertList signature algorithm");
  if (hexOf(b.subarray(innerAlg.pos, innerAlg.end)) !== hexOf(b.subarray(algT.pos, algT.end))) throw new DerError("signature algorithm differs between TBSCertList and CertificateList");
  const issuer = f[i++];
  if (issuer?.tag !== 0x30) throw new DerError("missing issuer");
  const thisT = f[i++];
  if (!isTime(thisT)) throw new DerError("missing thisUpdate");
  const nextT = isTime(f[i]) ? f[i++]! : null;
  const list = f[i]?.tag === 0x30 ? f[i++]! : null;
  if (f[i]?.tag === 0xa0) i++;
  if (i !== f.length) throw new DerError("unexpected field in TBSCertList");
  return { issuer, thisT, nextT, list };
}

/** Outer AlgorithmIdentifier: OID and DER parameters (null when absent or NULL). Also checks the BIT STRING. */
function readSignatureAlgorithm(b: Uint8Array, algT: Tlv, sigT: Tlv): { oid: string; params: Uint8Array | null } {
  const algParts = children(b, algT);
  const oid = readOid(b, algParts[0]!);
  const p = algParts[1];
  const params = p && p.tag !== 0x05 ? b.subarray(p.pos, p.end) : null;
  if (sigT.end - sigT.start < 1 || b[sigT.start] !== 0) throw new DerError("signature BIT STRING has unused bits");
  return { oid, params };
}

/** Index: serial (normalized hex) -> entry offset. Entries are decoded on lookup. */
function indexEntries(b: Uint8Array, list: Tlv | null): Map<string, number> {
  const index = new Map<string, number>();
  if (!list) return index;
  for (let q = list.start; q < list.end; ) {
    const e = readTlv(b, q, list.end);
    if (e.tag !== 0x30) throw new DerError(`revoked entry at ${e.pos} is not a SEQUENCE`);
    const serial = readTlv(b, e.start, e.end);
    if (serial.tag !== 0x02 || serial.end === serial.start) throw new DerError(`revoked entry at ${e.pos} has no serial number`);
    if (index.size >= MAX_CRL_ENTRIES) throw new DerError(`more than ${MAX_CRL_ENTRIES} entries`);
    index.set(hexOf(b.subarray(serial.start, serial.end)).replace(/^0+(?=.)/, ""), e.pos);
    q = e.end;
  }
  return index;
}

/** Applies one crlEntryExtension (reasonCode, invalidityDate) to `info`; others are ignored. */
function applyEntryExtension(b: Uint8Array, ext: Tlv, info: CrlEntryInfo): void {
  const parts = children(b, ext);
  const oid = readOid(b, parts[0]!);
  const octets = parts.at(-1)!;
  if (octets.tag !== 0x04) return;
  const v = readTlv(b, octets.start, octets.end);
  if (oid === "2.5.29.21" && v.tag === 0x0a) {
    let n = 0;
    for (let k = v.start; k < v.end; k++) n = n * 256 + b[k]!;
    info.reason = n;
  } else if (oid === "2.5.29.24" && v.tag === 0x18) info.invalidity = readTime(b, v);
}

function decodeEntry(b: Uint8Array, list: Tlv, pos: number): CrlEntryInfo {
  const e = readTlv(b, pos, list.end);
  const serial = readTlv(b, e.start, e.end);
  const date = readTlv(b, serial.end, e.end);
  if (!isTime(date)) throw new DerError(`entry at ${pos} has no revocation date`);
  const info: CrlEntryInfo = { revocationDate: readTime(b, date) };
  if (date.end < e.end) for (const ext of children(b, readTlv(b, date.end, e.end))) applyEntryExtension(b, ext, info);
  return info;
}

/** Parses a DER CRL. Throws DerError on anything that is not a well-formed, bounded CRL. */
export function parseCrlDer(input: Uint8Array): ParsedCrl {
  const b = input;
  const { tbsT, algT, sigT } = readEnvelope(b);
  const { issuer, thisT, nextT, list } = readTbsHeader(b, tbsT, algT);
  const alg = readSignatureAlgorithm(b, algT, sigT);
  const index = indexEntries(b, list);
  return {
    issuerDer: b.subarray(issuer.pos, issuer.end),
    thisUpdate: readTime(b, thisT),
    nextUpdate: nextT ? readTime(b, nextT) : null,
    tbs: b.subarray(tbsT.pos, tbsT.end),
    signatureAlgorithm: alg.oid,
    signatureAlgorithmParams: alg.params,
    signature: b.subarray(sigT.start + 1, sigT.end),
    entryCount: index.size,
    entry(serial: string) {
      const pos = index.get(serial);
      return pos === undefined || !list ? null : decodeEntry(b, list, pos);
    }
  };
}

/** Converts a DER ECDSA-Sig-Value to the raw r||s form Web Crypto verifies. */
export function ecdsaDerToRaw(sig: Uint8Array, size: number): Uint8Array {
  const seq = readTlv(sig, 0, sig.length);
  const [r, s] = children(sig, seq);
  if (!r || !s || r.tag !== 0x02 || s.tag !== 0x02) throw new DerError("bad ECDSA signature");
  const out = new Uint8Array(size * 2);
  for (const [t, off] of [[r, 0], [s, size]] as const) {
    let v = sig.subarray(t.start, t.end);
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    if (v.length > size) throw new DerError("bad ECDSA signature");
    out.set(v, off + size - v.length);
  }
  return out;
}
