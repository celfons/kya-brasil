// @kya-brasil/core against OpenSSL, on three things:
//   1. the entries of every CRL of the cut (data/crl, data/openssl): dates, count, and each serial, date and reason;
//   2. mutated CRLs: the core's reader must answer (a parsed list or a DerError) and never fail in another way,
//      and where both readers accept a mutant they must read the same dates; and, with the certificate of the AC
//      (anchors/icp-brasil.pem), the core must not verify a mutant whose signature OpenSSL refuses;
//   3. the CMS signature of the self-issued vector, and mutants of it: the core must not accept what OpenSSL refuses.
// Usage: tsx compare.mjs   (writes results/results.json and results/RESULTS.md)
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { verifyCrl, verifyIcpSignature } from "@kya-brasil/core";
import { DerError, parseCrlDer } from "../../packages/core/src/crl-der.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const CRL = join(HERE, "data", "crl");
const OPENSSL = join(HERE, "data", "openssl");
const TMP = mkdtempSync(join(tmpdir(), "kya-differential-"));
const SEED = 20261112;
const MUTANTS_PER_CRL = 200;
const OPENSSL_MAX_BYTES = 300_000; // mutants of larger lists are read only by the core, to keep the run short
const CMS_MUTANTS = 2000;
const iso = (d) => (d ? d.toISOString().replace(".000Z", "Z") : null);

/** mulberry32: a small seeded generator, so the mutants are the same on every run. */
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---------- 1. entries of the cut
/**
 * The hex of the content bytes of the INTEGER, without leading zeros, which is how the core indexes a serial.
 * OpenSSL prints a negative serial as a minus sign and the magnitude; RFC 5280 forbids them, and two Serpro lists
 * carry a few.
 */
function derSerial(printed) {
  if (!printed.startsWith("-")) return printed;
  const n = -BigInt("0x" + printed.slice(1));
  let bytes = 1;
  while (n < -(1n << BigInt(8 * bytes - 1))) bytes++;
  return (n + (1n << BigInt(8 * bytes))).toString(16).padStart(2 * bytes, "0").replace(/^0+(?=.)/, "");
}

function compareEntries(name, der, ref) {
  const crl = parseCrlDer(der);
  const diffs = [];
  if (iso(crl.thisUpdate) !== ref.this_update) diffs.push(`thisUpdate ${iso(crl.thisUpdate)} != ${ref.this_update}`);
  if (iso(crl.nextUpdate) !== ref.next_update) diffs.push(`nextUpdate ${iso(crl.nextUpdate)} != ${ref.next_update}`);
  const distinct = new Set(ref.entries.map((e) => derSerial(e[0]))).size;
  if (crl.entryCount !== distinct) diffs.push(`entries ${crl.entryCount} != ${distinct}`);
  let withReason = 0;
  let negative = 0;
  for (const [printed, date, reason] of ref.entries) {
    const serial = derSerial(printed);
    if (printed.startsWith("-")) negative++;
    const e = crl.entry(serial);
    if (!e) diffs.push(`serial ${serial} missing`);
    else if (iso(e.revocationDate) !== date || (e.reason ?? null) !== reason) diffs.push(`serial ${serial}: ${iso(e.revocationDate)}/${e.reason ?? null} != ${date}/${reason}`);
    if (reason !== null) withReason++;
    if (diffs.length > 5) break;
  }
  return { source: name, bytes: der.length, entries: ref.entries.length, distinct_serials: distinct, with_reason: withReason, negative_serials: negative, diffs };
}

// ---------- 2. mutated CRLs
function mutate(der, rnd) {
  const out = Uint8Array.from(der);
  const kind = Math.floor(rnd() * 4);
  if (kind === 0) out[Math.floor(rnd() * out.length)] ^= 1 << Math.floor(rnd() * 8); // one bit, anywhere
  else if (kind === 1) out[Math.floor(rnd() * Math.min(out.length, 256))] = Math.floor(rnd() * 256); // one byte of the header
  else if (kind === 2) return { kind: "truncate", bytes: out.subarray(0, 1 + Math.floor(rnd() * (out.length - 1))) };
  else {
    const at = Math.floor(rnd() * (out.length - 4)); // four random bytes in a row
    for (let k = 0; k < 4; k++) out[at + k] = Math.floor(rnd() * 256);
  }
  return { kind: ["bit", "header-byte", "truncate", "four-bytes"][kind], bytes: out };
}

function coreReads(bytes, serials) {
  const t0 = performance.now();
  try {
    const crl = parseCrlDer(bytes);
    for (const s of serials) crl.entry(s);
    return { ok: true, this_update: iso(crl.thisUpdate), next_update: iso(crl.nextUpdate), ms: performance.now() - t0 };
  } catch (e) {
    return { ok: false, refused: e instanceof DerError, error: `${e?.name}: ${e?.message}`.slice(0, 160), ms: performance.now() - t0 };
  }
}

/** A date as OpenSSL prints it; when OpenSSL prints something that is not a date, that text, marked. */
function opensslDate(s) {
  const d = new Date(s.replace(/\s+/g, " ").replace(" GMT", " UTC"));
  return Number.isNaN(d.getTime()) ? `not a date: ${s.trim()}` : iso(d);
}
function opensslReads(bytes) {
  const path = join(TMP, "mutant.crl");
  writeFileSync(path, bytes);
  const r = spawnSync("openssl", ["crl", "-inform", "DER", "-in", path, "-noout", "-lastupdate", "-nextupdate"], { encoding: "utf8" });
  if (r.status !== 0) return { ok: false };
  const last = /lastUpdate=(.*)/.exec(r.stdout)?.[1];
  const next = /nextUpdate=(.*)/.exec(r.stdout)?.[1];
  return { ok: true, this_update: last ? opensslDate(last) : null, next_update: next && next !== "NONE" ? opensslDate(next) : null };
}

/** The anchors as PEM blocks, and for a CRL the one whose key verifies it (by the core), or null. */
const ANCHORS = readFileSync(join(HERE, "..", "..", "anchors", "icp-brasil.pem"), "utf8").match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [];
async function coreVerifiesCrl(bytes, issuerCertificate) {
  try {
    await verifyCrl({ crlDer: bytes, issuerCertificate, pastNextUpdate: "accept" });
    return true;
  } catch {
    return false;
  }
}
async function issuerOf(der) {
  for (const pem of ANCHORS) if (await coreVerifiesCrl(der, pem)) return pem;
  return null;
}
function opensslVerifiesCrl(bytes, issuerPath) {
  const path = join(TMP, "mutant.crl");
  writeFileSync(path, bytes);
  const r = spawnSync("openssl", ["crl", "-inform", "DER", "-in", path, "-CAfile", issuerPath, "-noout"], { encoding: "utf8" });
  return r.status === 0 && /verify OK/.test(r.stderr);
}

async function mutateCrls(names) {
  const rnd = prng(SEED);
  const tally = { mutants: 0, core_parsed: 0, core_refused: 0, core_other_error: 0, slowest_ms: 0, compared_with_openssl: 0, both_accept: 0, both_refuse: 0, only_core_accepts: 0, only_openssl_accepts: 0, dates_differ: 0 };
  const signature = { lists: 0, mutants: 0, both_verify: 0, both_refuse: 0, only_core_verifies: 0, only_openssl_verifies: 0 };
  const examples = { core_other_error: [], only_core_accepts: [], only_openssl_accepts: [], dates_differ: [], only_core_verifies: [], only_openssl_verifies: [] };
  const issuerPath = join(TMP, "issuer.pem");
  const note = (k, v) => { if (examples[k].length < 10) examples[k].push(v); };
  for (const name of names) {
    const der = readFileSync(join(CRL, name + ".crl"));
    const serials = JSON.parse(readFileSync(join(OPENSSL, name + ".json"), "utf8")).entries.slice(0, 50).map((e) => derSerial(e[0]));
    // The signature is compared only where the AC's certificate is among the anchors and both verify the original.
    let issuer = der.length > OPENSSL_MAX_BYTES ? null : await issuerOf(der);
    if (issuer) {
      writeFileSync(issuerPath, issuer + "\n");
      if (opensslVerifiesCrl(der, issuerPath)) signature.lists++;
      else issuer = null;
    }
    for (let i = 0; i < MUTANTS_PER_CRL; i++) {
      const m = mutate(der, rnd);
      const c = coreReads(m.bytes, serials);
      tally.mutants++;
      tally.slowest_ms = Math.max(tally.slowest_ms, Math.round(c.ms));
      if (c.ok) tally.core_parsed++;
      else if (c.refused) tally.core_refused++;
      else { tally.core_other_error++; note("core_other_error", { source: name, mutant: i, kind: m.kind, error: c.error }); }
      if (der.length > OPENSSL_MAX_BYTES) continue;
      const o = opensslReads(m.bytes);
      tally.compared_with_openssl++;
      if (c.ok && o.ok) {
        tally.both_accept++;
        if (c.this_update !== o.this_update || c.next_update !== o.next_update) { tally.dates_differ++; note("dates_differ", { source: name, mutant: i, kind: m.kind, core: [c.this_update, c.next_update], openssl: [o.this_update, o.next_update] }); }
      } else if (!c.ok && !o.ok) tally.both_refuse++;
      else if (c.ok) { tally.only_core_accepts++; note("only_core_accepts", { source: name, mutant: i, kind: m.kind }); }
      else { tally.only_openssl_accepts++; note("only_openssl_accepts", { source: name, mutant: i, kind: m.kind, error: c.error }); }
      if (!issuer) continue;
      const cv = await coreVerifiesCrl(m.bytes, issuer);
      const ov = opensslVerifiesCrl(m.bytes, issuerPath);
      signature.mutants++;
      if (cv && ov) signature.both_verify++;
      else if (!cv && !ov) signature.both_refuse++;
      else if (cv) { signature.only_core_verifies++; note("only_core_verifies", { source: name, mutant: i, kind: m.kind }); }
      else { signature.only_openssl_verifies++; note("only_openssl_verifies", { source: name, mutant: i, kind: m.kind }); }
    }
  }
  return { tally, signature, examples };
}

// ---------- 3. the CMS signature of the self-issued vector
async function coreVerifies(cmsBase64, challenge, v) {
  try {
    await verifyIcpSignature({ cmsBase64, challenge, expectedCnpj: v.credential.principal.cnpj, anchors: v.anchors, now: new Date(v.verify_at) });
    return { ok: true };
  } catch (e) {
    return { ok: false, error: `${e?.code ?? e?.name}: ${e?.message}`.slice(0, 160) };
  }
}

function opensslVerifies(cms, text, caPath, at) {
  const p7 = join(TMP, "p7.der");
  const content = join(TMP, "content");
  writeFileSync(p7, cms);
  writeFileSync(content, text);
  const r = spawnSync("openssl", ["cms", "-verify", "-binary", "-inform", "DER", "-in", p7, "-content", content, "-CAfile", caPath, "-attime", String(at), "-purpose", "any", "-out", "/dev/null"], { encoding: "utf8" });
  return r.status === 0;
}

async function compareCms() {
  const v = JSON.parse(readFileSync(join(HERE, "..", "..", "docs", "vectors", "self-issued-v1.json"), "utf8"));
  const caPath = join(TMP, "ca.pem");
  writeFileSync(caPath, v.anchors.map((a) => `-----BEGIN CERTIFICATE-----\n${a}\n-----END CERTIFICATE-----\n`).join(""));
  const at = Math.floor(new Date(v.verify_at).getTime() / 1000);
  const cms = Buffer.from(v.proof.cms, "base64");
  const text = v.proof.text;
  const original = { core: (await coreVerifies(v.proof.cms, text, v)).ok, openssl: opensslVerifies(cms, text, caPath, at) };
  const changedText = text.replace("agent:", "agent :");
  const otherText = { core: (await coreVerifies(v.proof.cms, changedText, v)).ok, openssl: opensslVerifies(cms, changedText, caPath, at) };
  const rnd = prng(SEED + 1);
  const tally = { mutants: CMS_MUTANTS, both_accept: 0, both_refuse: 0, only_core_accepts: 0, only_openssl_accepts: 0 };
  const examples = { only_core_accepts: [], only_openssl_accepts: [] };
  for (let i = 0; i < CMS_MUTANTS; i++) {
    const m = Buffer.from(cms);
    const at_ = Math.floor(rnd() * m.length);
    m[at_] ^= 1 << Math.floor(rnd() * 8);
    const c = await coreVerifies(m.toString("base64"), text, v);
    const o = opensslVerifies(m, text, caPath, at);
    if (c.ok && o) tally.both_accept++;
    else if (!c.ok && !o) tally.both_refuse++;
    else if (c.ok) { tally.only_core_accepts++; examples.only_core_accepts.push({ mutant: i, offset: at_, byte_before: cms[at_], byte_after: m[at_] }); }
    else { tally.only_openssl_accepts++; if (examples.only_openssl_accepts.length < 10) examples.only_openssl_accepts.push({ mutant: i, offset: at_, error: c.error }); }
  }
  return { cms_bytes: cms.length, original, other_text: otherText, tally, examples };
}

// ---------- run
const names = readdirSync(CRL).filter((n) => n.endsWith(".crl")).map((n) => n.slice(0, -4)).sort();
const measured = JSON.parse(readFileSync(join(HERE, "..", "freshness-sim", "data", "measured.json"), "utf8"));
const lists = names.map((n) => compareEntries(n, readFileSync(join(CRL, n + ".crl")), JSON.parse(readFileSync(join(OPENSSL, n + ".json"), "utf8"))));
const mutated = await mutateCrls(names);
const cms = await compareCms();
rmSync(TMP, { recursive: true, force: true });

const core = JSON.parse(readFileSync(join(HERE, "..", "..", "packages", "core", "package.json"), "utf8")).version;
const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: HERE, encoding: "utf8" }).trim();
const results = {
  cut: measured.generated_at,
  core_version: core,
  commit,
  openssl: readFileSync(join(OPENSSL, "version.txt"), "utf8").trim(),
  seed: SEED,
  entries: {
    lists: lists.length,
    entries: lists.reduce((a, l) => a + l.entries, 0),
    with_reason: lists.reduce((a, l) => a + l.with_reason, 0),
    negative_serials: lists.reduce((a, l) => a + l.negative_serials, 0),
    lists_that_differ: lists.filter((l) => l.diffs.length).length,
    differences: lists.filter((l) => l.diffs.length).map((l) => ({ source: l.source, diffs: l.diffs })),
    per_list: lists.map(({ diffs, ...l }) => l)
  },
  mutated_crls: { mutants_per_list: MUTANTS_PER_CRL, openssl_max_bytes: OPENSSL_MAX_BYTES, ...mutated },
  cms
};
mkdirSync(join(HERE, "results"), { recursive: true });
writeFileSync(join(HERE, "results", "results.json"), JSON.stringify(results, null, 2) + "\n");
const t = mutated.tally;
const g = mutated.signature;
const c = cms.tally;
writeFileSync(join(HERE, "results", "RESULTS.md"), `# Differential test against OpenSSL

Cut of ${results.cut}, @kya-brasil/core ${core} (commit ${commit.slice(0, 12)}), ${results.openssl}. Seed ${SEED}.

## Entries of the CRLs of the cut

| Lists | Entries | With reason | Lists that differ |
|---:|---:|---:|---:|
| ${results.entries.lists} | ${results.entries.entries} | ${results.entries.with_reason} | ${results.entries.lists_that_differ} |

## Mutated CRLs

${MUTANTS_PER_CRL} mutants of each list (one bit, one header byte, a truncation or four bytes in a row).

| Mutants | Core parsed | Core refused (DerError) | Core failed otherwise | Slowest (ms) |
|---:|---:|---:|---:|---:|
| ${t.mutants} | ${t.core_parsed} | ${t.core_refused} | ${t.core_other_error} | ${t.slowest_ms} |

Mutants of lists up to ${OPENSSL_MAX_BYTES} bytes were also given to OpenSSL.

| Compared | Both accept | Both refuse | Only the core accepts | Only OpenSSL accepts | Dates differ |
|---:|---:|---:|---:|---:|---:|
| ${t.compared_with_openssl} | ${t.both_accept} | ${t.both_refuse} | ${t.only_core_accepts} | ${t.only_openssl_accepts} | ${t.dates_differ} |

With the certificate of the AC, taken from \`anchors/icp-brasil.pem\`, the signature of each mutant was verified by
both, for the ${g.lists} lists whose AC is there and whose original both verify.

| Mutants | Both verify | Both refuse | Only the core verifies | Only OpenSSL verifies |
|---:|---:|---:|---:|---:|
| ${g.mutants} | ${g.both_verify} | ${g.both_refuse} | ${g.only_core_verifies} | ${g.only_openssl_verifies} |

## CMS signature of the self-issued vector

| Case | Core | OpenSSL |
|---|---|---|
| The vector | ${cms.original.core ? "accepts" : "refuses"} | ${cms.original.openssl ? "accepts" : "refuses"} |
| The same signature over another text | ${cms.other_text.core ? "accepts" : "refuses"} | ${cms.other_text.openssl ? "accepts" : "refuses"} |

${CMS_MUTANTS} mutants of the signature, one bit each.

| Both accept | Both refuse | Only the core accepts | Only OpenSSL accepts |
|---:|---:|---:|---:|
| ${c.both_accept} | ${c.both_refuse} | ${c.only_core_accepts} | ${c.only_openssl_accepts} |
`);
console.log(JSON.stringify({ entries: { lists: results.entries.lists, entries: results.entries.entries, lists_that_differ: results.entries.lists_that_differ }, mutated_crls: t, mutated_crl_signatures: g, cms: { original: cms.original, other_text: cms.other_text, ...c } }, null, 2));
