// TEST ONLY: benchmarks on the worthless PKI from examples/quickstart/make-test-pki.mjs (written to ./out by `pnpm bench`).
//
// Measures latency (median, p95, ops/s) of issuance, self-issued verification, co-signature, agent request signing,
// offline authentication, delegation chains and CRL handling, plus the size of what goes on the wire.
// Writes results.json and RESULTS.md next to this file (with BENCH_SMOKE=1: into ./out, so committed results are untouched).
//
// Env: BENCH_N (default 1000) iterations for fast operations; slow ones use fewer, stated in the table.
//      BENCH_CRL_ENTRIES (default 77000) entries of the synthetic large CRL.
import "reflect-metadata";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { cpus, arch, platform, release, totalmem } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import * as x509 from "@peculiar/x509";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  addCosignature, assembleCredential, buildMandate, checkRevocation, encodeDelegationHeader, encodePrincipalProofHeader,
  evidenceFromRevocation, mandateSigningInput, openPfx, verifyCompanyWill, verifyCrl, verifyDelegationChain, verifySelfIssuedCredential
} from "@kya-brasil/core";
import { createKyaAuth, memoryReplayCache, signDelegation, signRequest } from "@kya-brasil/agent-tools";

x509.cryptoProvider.set(globalThis.crypto);
const HERE = import.meta.dirname;
const OUT = resolve(process.env.KYA_QUICKSTART_OUT ?? join(HERE, "out"));
const SMOKE = process.env.BENCH_SMOKE === "1";
const N = Number(process.env.BENCH_N ?? 1000);
const CRL_ENTRIES = Number(process.env.BENCH_CRL_ENTRIES ?? (SMOKE ? 1000 : 77_000));
const slow = (n) => Math.max(SMOKE ? 3 : 10, Math.min(N, n)); // iteration count for slow operations
const read = (f) => readFileSync(join(OUT, f));
const fail = (why, detail) => { console.error(`FAIL: ${why}`, detail === undefined ? "" : JSON.stringify(detail, null, 2)); process.exit(1); };

const pki = JSON.parse(read("pki.json"));
const agent = JSON.parse(read("agent.json"));
const agentKey = { kind: "evm", privateKey: agent.privateKey };
const anchors = read("anchors.pem").toString().match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
const now = new Date();

// ---- harness -----------------------------------------------------------------------------------------------
const results = [];
const quantile = (sorted, q) => sorted[Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1)];
/** Runs `fn(i)` `warmup` times, then `n` times timed one by one. `setup(i)` (untimed) prepares each iteration's input. */
async function bench(id, label, n, fn, { warmup = Math.max(5, Math.ceil(n / 10)), setup } = {}) {
  for (let i = 0; i < warmup; i++) await fn(setup ? await setup(-1 - i) : undefined);
  const ms = [];
  for (let i = 0; i < n; i++) {
    const input = setup ? await setup(i) : undefined;
    const t0 = performance.now();
    await fn(input);
    ms.push(performance.now() - t0);
  }
  ms.sort((a, b) => a - b);
  const r = { id, label, n, warmup, median_ms: +quantile(ms, 0.5).toFixed(4), p95_ms: +quantile(ms, 0.95).toFixed(4), mean_ms: +(ms.reduce((a, b) => a + b, 0) / n).toFixed(4), min_ms: +ms[0].toFixed(4), max_ms: +ms[n - 1].toFixed(4) };
  r.ops_per_s = r.median_ms > 0 ? +(1000 / r.median_ms).toFixed(1) : null; // sub-microsecond: below timer resolution
  results.push(r);
  console.log(`${label.padEnd(64)} n=${String(n).padStart(4)}  median ${r.median_ms.toFixed(3)} ms  p95 ${r.p95_ms.toFixed(3)} ms  ${r.ops_per_s ?? ">1e6"} ops/s`);
  return r;
}
const sizes = {};

// ---- 1. issuance -------------------------------------------------------------------------------------------
const input = JSON.parse(readFileSync(join(HERE, "../../examples/quickstart/mandate-input.json"), "utf8"));
input.agent = { kind: "evm", id: agent.id };
input.mandate.valid_from = new Date(now.getTime() - 60_000).toISOString();
input.mandate.valid_until = new Date(now.getTime() + 90 * 86_400_000).toISOString();
input.mandate.delegation = { max_depth: 3, max_ttl_seconds: 3600 }; // so the same credential serves the delegation benchmarks
const company = await openPfx(read("company.pfx"), pki.password); // opening the A1 file is one-off, not timed
const rep = await openPfx(read("representative.pfx"), pki.password);

async function issue() {
  const built = await buildMandate({ ...input, credential_id: crypto.randomUUID(), now });
  const { text } = await mandateSigningInput(built);
  const cms = await company.sign(text);
  return assembleCredential(built, cms, [], { anchors, now });
}
let issued;
await bench("issuance", "1. issuance: buildMandate + signingInput + RSA sign (A1) + assemble", slow(300), async () => { issued = await issue(); });
// RSA signature alone, to separate it from the chain verification inside assembleCredential.
const text0 = issued.proof.text;
await bench("rsa_sign_cms", "1a. e-CNPJ A1 sign only (detached CMS, RSA-2048)", N, () => company.sign(text0));

// ---- 2. verifySelfIssuedCredential -------------------------------------------------------------------------
await bench("verify_self_issued", "2. verifySelfIssuedCredential (proof vs anchors)", slow(500), async () => {
  const r = await verifySelfIssuedCredential({ credential: issued.credential, proof: issued.proof, anchors, now });
  if (!r.ok) fail("verifySelfIssuedCredential", r.checks);
});

// ---- 3. co-signature ---------------------------------------------------------------------------------------
const repCms = await rep.sign(issued.proof.text);
let cosigned;
await bench("add_cosignature", "3a. addCosignature (e-CPF CMS already signed)", slow(500), async () => { cosigned = await addCosignature(issued, repCms, [], { anchors, now }); });
await bench("verify_company_will", "3b. verifyCompanyWill (1 co-signer)", slow(500), async () => {
  const w = await verifyCompanyWill(cosigned, { anchors, now, representatives: () => [pki.representative_cpf], minCosigners: 1 });
  if (!w.ok) fail("verifyCompanyWill", w);
});

// ---- 4. agent signRequest and offline authentication -------------------------------------------------------
const { credential, proof } = issued;
const url = "https://fornecedor.example/api/pay";
const bodyOf = (i) => JSON.stringify({ amount: 100, currency: "BRL", to: "33000167000101", nonce: i });
await bench("sign_request", "4a. agent signRequest (EVM, with present)", N, (i) => signRequest({ credentialId: credential.credential_id, key: agentKey, method: "POST", url, body: bodyOf(i ?? 0), present: { credential, proof } }), { setup: (i) => i });

const smallCrl = new Uint8Array(read("ac.crl"));
let crlCached = null;
async function certificateStatus({ revocation }) {
  if (!crlCached) crlCached = await verifyCrl({ crlDer: smallCrl, issuerCertificate: revocation.issuer_certificate, pastNextUpdate: "refuse", now: new Date() });
  return evidenceFromRevocation(crlCached.lookup(revocation.serial_number), revocation.crl_urls[0]);
}
const auth = createKyaAuth({ replayCache: memoryReplayCache(), offline: { anchors, now: () => new Date(), certificateStatus } });
const requestFor = async (i) => {
  const body = bodyOf(i);
  const headers = await signRequest({ credentialId: credential.credential_id, key: agentKey, method: "POST", url, body, present: { credential, proof } });
  return new Request(url, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });
};
await bench("authenticate_offline", "4b. createKyaAuth offline: authenticate + check() (CRL cached)", slow(500), async (req) => {
  const r = await auth.authenticate(req);
  if (!r.ok) fail("authenticate", r);
  if (!r.kya.check({ action: "pay", amount: 100, currency: "BRL", counterparty: "33000167000101" }).allowed) fail("check");
}, { setup: (i) => requestFor(1e6 + i) });

const headers = await signRequest({ credentialId: credential.credential_id, key: agentKey, method: "POST", url, body: bodyOf(0), present: { credential, proof } });
const headersCosigned = await signRequest({ credentialId: credential.credential_id, key: agentKey, method: "POST", url, body: bodyOf(0), present: { credential: cosigned.credential, proof: cosigned.proof } });
const headerBytes = (h) => Object.entries(h).reduce((s, [k, v]) => s + Buffer.byteLength(`${k}: ${v}\r\n`), 0);
sizes.credential_json = Buffer.byteLength(JSON.stringify(credential));
sizes.credential_and_proof_json = Buffer.byteLength(JSON.stringify(issued));
sizes.principal_proof_header = encodePrincipalProofHeader(proof).length;
sizes.principal_proof_header_1_cosignature = encodePrincipalProofHeader(cosigned.proof).length;
sizes.request_headers_total = headerBytes(headers);
sizes.request_headers_total_1_cosignature = headerBytes(headersCosigned);
sizes.request_header_names = Object.keys(headers);
sizes.request_headers_each = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, v.length]));

// ---- 5. delegation chains ----------------------------------------------------------------------------------
const subMandate = (depthLeft) => ({ actions: ["pay"], max_per_operation: { amount: 1000, currency: "BRL" }, max_per_day: { amount: 5000, currency: "BRL" }, currencies: ["BRL"], counterparties: ["33000167000101"], payment_instruments: [], valid_from: input.mandate.valid_from, valid_until: input.mandate.valid_until, ...(depthLeft > 0 ? { delegation: { max_depth: depthLeft, max_ttl_seconds: 3600 } } : {}) });
const chains = [];
let chain = [];
let signer = agentKey;
for (let d = 1; d <= 3; d++) {
  const pk = generatePrivateKey();
  chain = await signDelegation({ credential, key: signer, delegate: { kind: "evm", id: privateKeyToAccount(pk).address }, mandate: subMandate(3 - d), ttlSeconds: 3600 - d * 60, chain });
  signer = { kind: "evm", privateKey: pk };
  chains.push(chain);
}
sizes.delegation_header = {};
for (const c of chains) {
  const d = c.length;
  const v = await verifyDelegationChain({ credential, chain: c, now: new Date() });
  if (!v.ok) fail(`verifyDelegationChain depth ${d}`, v);
  sizes.delegation_header[`depth_${d}`] = encodeDelegationHeader(c).length;
  await bench(`delegation_depth_${d}`, `5. verifyDelegationChain depth ${d}`, N, async () => {
    const r = await verifyDelegationChain({ credential, chain: c, now: new Date() });
    if (!r.ok) fail("verifyDelegationChain", r);
  });
}

// ---- 6. CRL ------------------------------------------------------------------------------------------------
const acPem = anchors[1];
const acB64 = acPem.replace(/-----[^-]+-----|\s+/g, "");
const leafSerial = "1001"; // company e-CNPJ serial in make-test-pki.mjs
sizes.crl_small = smallCrl.byteLength;
await bench("crl_small_check", "6a. checkRevocation small CRL (parse+verify+lookup)", N, async () => {
  const s = await checkRevocation({ crlDer: smallCrl, serial: leafSerial, issuerCertificate: acB64, pastNextUpdate: "refuse" });
  if (s.revoked) fail("small CRL revoked the leaf");
});
const smallVerified = await verifyCrl({ crlDer: smallCrl, issuerCertificate: acB64, pastNextUpdate: "refuse" });
await bench("crl_small_lookup", "6a. lookup on verified small CRL", N, () => smallVerified.lookup(leafSerial));

// Large CRL: its own throwaway AC (make-test-pki.mjs does not keep the AC key), RSA-2048 like the quickstart,
// CRL_ENTRIES random 16-byte serials with revocation date and reason, like an ICP-Brasil AC's CRL.
// Generated with the openssl CLI (`openssl ca -gencrl`): @peculiar/x509's X509CrlGenerator re-parses what it
// builds with asn1js's 10 000-node default, so it cannot produce one this large.
const reasonNames = ["keyCompromise", "superseded", "cessationOfOperation", "affiliationChanged"];
const serials = Array.from({ length: CRL_ENTRIES }, () => "4" + Buffer.from(crypto.getRandomValues(new Uint8Array(15))).toString("hex").toUpperCase().slice(1));
function opensslCrl(dir, entries) {
  mkdirSync(dir, { recursive: true });
  const sh = (cmd) => execFileSync("sh", ["-c", cmd], { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
  const t = (ms) => new Date(ms).toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z";
  writeFileSync(join(dir, "index.txt"), entries.map((s, i) => `R\t${t(now.getTime() + 365 * 86_400_000)}\t${t(now.getTime() - (i % 1000) * 3_600_000)},${reasonNames[i % 4]}\t${s}\tunknown\t/CN=revogado${i}\n`).join(""));
  writeFileSync(join(dir, "ca.cnf"), "[ca]\ndefault_ca=x\n[x]\ndatabase=index.txt\ncrlnumber=crlnumber\ndefault_md=sha256\ndefault_crl_days=7\ncertificate=ac.pem\nprivate_key=ac.key\ncrl_extensions=ext\n[ext]\nauthorityKeyIdentifier=keyid:always\n");
  writeFileSync(join(dir, "crlnumber"), "01\n");
  sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout ac.key -out ac.pem -days 365 -subj "/C=BR/O=ICP-Brasil TESTE/CN=AC GRANDE TESTE SEM VALOR" 2>/dev/null');
  sh("openssl ca -config ca.cnf -gencrl -out crl.pem -batch 2>/dev/null && openssl crl -in crl.pem -outform DER -out crl.der");
  return { der: new Uint8Array(readFileSync(join(dir, "crl.der"))), acB64: readFileSync(join(dir, "ac.pem"), "utf8").replace(/-----[^-]+-----|\s+/g, "") };
}
let t0 = performance.now();
const big = opensslCrl(join(OUT, "large-crl"), serials);
console.log(`generated a ${CRL_ENTRIES}-entry CRL (${big.der.byteLength} bytes) with openssl in ${(performance.now() - t0).toFixed(0)} ms`);
sizes.crl_large = big.der.byteLength;
sizes.crl_large_entries = CRL_ENTRIES;
const probe = (list) => (i) => (i % 2 ? list[(i * 7919) % list.length] : "5" + (i + 1).toString(16).padStart(31, "0")); // half hits, half misses

// Library code path on the large CRL (refused before core 0.19.1, see `findings`).
const findings = [];
let bigVerified;
await bench("crl_large_verify", `6b. verifyCrl synthetic CRL (${CRL_ENTRIES} entries: parse+verify+index)`, slow(50), async () => { bigVerified = await verifyCrl({ crlDer: big.der, issuerCertificate: big.acB64, pastNextUpdate: "refuse" }); }, { warmup: 3 });
await bench("crl_large_lookup", `6b. lookup on verified ${CRL_ENTRIES}-entry CRL (50% hits)`, N, (i) => bigVerified.lookup(probe(serials)(i)), { setup: (i) => Math.abs(i) });
if (!bigVerified.lookup(serials[0]).revoked || bigVerified.lookup("5ff").revoked) fail("large CRL lookup is wrong");

// The real AC SERPRO RFB v5 CRL, latest copy kept by the public kya-icp collector, verified against the AC
// certificate in anchors/icp-brasil.pem. Full runs only (needs the network); skipped, and said so, if unreachable.
if (!SMOKE && process.env.BENCH_SERPRO !== "0") {
  const base = "https://kya-icp-collector.marcelfons.workers.dev";
  try {
    const list = await (await fetch(`${base}/api/files/uf-ac-serpro-rfb-v5`, { headers: { "user-agent": "curl/8" } })).json();
    const key = list.files.map((f) => f.key).sort().at(-1);
    const der = new Uint8Array(await (await fetch(`${base}/files/${key}`, { headers: { "user-agent": "curl/8" } })).arrayBuffer());
    const pems = readFileSync(join(HERE, "../../anchors/icp-brasil.pem"), "utf8").match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
    const acCert = pems.find((p) => new x509.X509Certificate(p).subject.includes("CN=Autoridade Certificadora SERPRORFBv5"));
    if (!acCert) throw new Error("AC SERPRO RFB v5 certificate not in anchors/icp-brasil.pem");
    let real;
    await bench("crl_serpro_verify", "6c. verifyCrl real AC SERPRO RFB v5 CRL (parse+verify+index)", slow(50), async () => { real = await verifyCrl({ crlDer: der, issuerCertificate: acCert, pastNextUpdate: "accept" }); }, { warmup: 3 });
    await bench("crl_serpro_lookup", "6c. lookup on verified SERPRO RFB v5 CRL", N, (i) => real.lookup((i * 2654435761 >>> 0).toString(16)), { setup: (i) => Math.abs(i) });
    sizes.crl_serpro = der.byteLength;
    sizes.crl_serpro_source = { key, sha256: Buffer.from(await crypto.subtle.digest("SHA-256", der)).toString("hex"), this_update: real.this_update, next_update: real.next_update };
    console.log(`SERPRO RFB v5 CRL ${key}: ${der.byteLength} bytes`);
  } catch (e) {
    console.log(`SKIPPED real SERPRO CRL: ${e.message}`);
    sizes.crl_serpro_source = { skipped: e.message };
  }
}

findings.push({
  id: "crl_large_refused_before_0_19_1", fixed_in: "@kya-brasil/core 0.19.1",
  before: "verifyCrl refused any CRL above about 1 240 entries (\"Maximum ASN.1 node count exceeded\": asn1js default maxNodes = 10 000 via @peculiar/x509 X509Crl), so the 77 000-entry SERPRO RFB v5 CRL could not be verified. Measured with core 0.19.0 on this machine: refused after 56 ms; largest accepted 1 244 entries (60 175 bytes), verifyCrl 109 ms median; the full 77k CRL parse+verify+index with asn1js maxNodes raised (reference outside the library): 3 658 ms median, 4 125 ms p95.",
  after: "core 0.19.1 parses the CRL with its own bounded DER reader (64 MiB, 2 000 000 entries), indexes serials by offset and decodes an entry only on lookup; the signature is verified over the TBSCertList bytes with Web Crypto."
});

// ---- smoke assertions: sizes in ranges, never timings ----------------------------------------------------------
// RSA-2048 signatures have a fixed size, but JSON carries UUIDs, timestamps and DER of varying length: ranges only.
if (SMOKE) {
  const inRange = (name, v, lo, hi) => { if (!(v >= lo && v <= hi)) fail(`size ${name} = ${v} outside [${lo}, ${hi}]`); };
  inRange("credential_json", sizes.credential_json, 1000, 2000);
  inRange("principal_proof_header", sizes.principal_proof_header, 4500, 7500);
  inRange("principal_proof_header_1_cosignature", sizes.principal_proof_header_1_cosignature, 9000, 14000);
  inRange("request_headers_total", sizes.request_headers_total, 6500, 10000);
  inRange("delegation depth_1", sizes.delegation_header.depth_1, 700, 1300);
  inRange("delegation depth_2", sizes.delegation_header.depth_2, 1600, 2600);
  inRange("delegation depth_3", sizes.delegation_header.depth_3, 2500, 3800);
  inRange("crl_small", sizes.crl_small, 350, 550);
  inRange("crl_large bytes per entry", sizes.crl_large / CRL_ENTRIES, 35, 60);
  console.log("smoke: size assertions passed (no timing thresholds)");
}

// ---- output ------------------------------------------------------------------------------------------------
const pkgVersion = (p) => JSON.parse(readFileSync(join(HERE, p), "utf8")).version;
const env = {
  date: new Date().toISOString(), node: process.version, v8: process.versions.v8, openssl: process.versions.openssl,
  os: `${platform()} ${release()} (${arch()})`, cpu: cpus()[0]?.model ?? "unknown", cpu_count: cpus().length, total_mem_gb: +(totalmem() / 2 ** 30).toFixed(1),
  packages: {
    "@kya-brasil/core": pkgVersion("../../packages/core/package.json"), "@kya-brasil/agent-tools": pkgVersion("../../packages/agent-tools/package.json"),
    "@peculiar/x509": pkgVersion("node_modules/@peculiar/x509/package.json"), "node-forge": pkgVersion("node_modules/node-forge/package.json"), viem: pkgVersion("node_modules/viem/package.json")
  },
  n_default: N, smoke: SMOKE, github_run_id: process.env.GITHUB_RUN_ID ?? null, runner: process.env.RUNNER_NAME ?? null
};
const json = { warning: "TEST ONLY: measured on a throwaway test PKI (examples/quickstart/make-test-pki.mjs)", env, results, sizes, findings };
const f = (x) => (x < 1 ? x.toFixed(3) : x < 100 ? x.toFixed(2) : x.toFixed(0));
const md = [
  "# KYA Brasil benchmarks", "",
  `Generated by \`pnpm --filter @kya-brasil/research-bench bench\` on ${env.date}. TEST ONLY PKI (RSA-2048, made up by examples/quickstart/make-test-pki.mjs).`, "",
  `Node ${env.node} (V8 ${env.v8}, OpenSSL ${env.openssl}), ${env.os}, ${env.cpu} x${env.cpu_count}, ${env.total_mem_gb} GB. ` +
  `@kya-brasil/core ${env.packages["@kya-brasil/core"]}, agent-tools ${env.packages["@kya-brasil/agent-tools"]}, @peculiar/x509 ${env.packages["@peculiar/x509"]}, node-forge ${env.packages["node-forge"]}, viem ${env.packages.viem}.`, "",
  "Each operation is warmed up, then timed one call at a time (`performance.now()`); ops/s = 1000 / median, single-threaded.", "",
  "| Operation | N | Median (ms) | p95 (ms) | ops/s |", "|---|---:|---:|---:|---:|",
  ...results.map((r) => `| ${r.label} | ${r.n} | ${f(r.median_ms)} | ${f(r.p95_ms)} | ${r.ops_per_s ?? "> 10^6"} |`), "",
  "## Sizes (bytes)", "", "| Item | Bytes |", "|---|---:|",
  `| Credential JSON | ${sizes.credential_json} |`, `| Credential + proof JSON (\`{ credential, proof }\`) | ${sizes.credential_and_proof_json} |`,
  `| KYA-Principal-Proof header | ${sizes.principal_proof_header} |`, `| KYA-Principal-Proof header, 1 co-signature | ${sizes.principal_proof_header_1_cosignature} |`,
  `| All request headers (${sizes.request_header_names.length}: ${sizes.request_header_names.join(", ")}) | ${sizes.request_headers_total} |`,
  `| All request headers, 1 co-signature | ${sizes.request_headers_total_1_cosignature} |`,
  ...Object.entries(sizes.delegation_header).map(([k, v]) => `| KYA-Delegation header, ${k.replace("_", " ")} | ${v} |`),
  `| Small test CRL (1 entry) | ${sizes.crl_small} |`, `| Synthetic large CRL (${sizes.crl_large_entries} entries) | ${sizes.crl_large} |`, ...(sizes.crl_serpro ? [`| Real AC SERPRO RFB v5 CRL | ${sizes.crl_serpro} |`] : []), "",
  ...(findings.length ? ["## Findings", "", ...findings.map((x) => `- **Found by this benchmark, fixed in ${x.fixed_in}.** Before: ${x.before} After: ${x.after}`), ""] : []),
  ...(sizes.crl_serpro ? [`Real CRL: \`${sizes.crl_serpro_source.key}\` (${sizes.crl_serpro} bytes, SHA-256 ${sizes.crl_serpro_source.sha256}, thisUpdate ${sizes.crl_serpro_source.this_update}), from the public kya-icp collector.`, ""] : [])
].join("\n");
const dest = SMOKE ? OUT : HERE;
writeFileSync(join(dest, "results.json"), JSON.stringify(json, null, 2) + "\n");
writeFileSync(join(dest, "RESULTS.md"), md);
console.log(`\n${md}\nwritten to ${dest}/results.json and RESULTS.md`);
