#!/usr/bin/env node
/**
 * Uploads the ICP-Brasil trust anchors to the Worker's KV (key `icp:anchors`) as one PEM bundle.
 * Without anchors the issuer refuses every e-CNPJ proof (fail closed; apps/worker/src/anchors.ts).
 *
 * Sources (ITI, the national root CA):
 *   roots  https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv*.crt   (default)
 *   all    https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip
 *          every accredited AC (roots + intermediates); use it when CMS signatures arrive without
 *          their intermediate certificates.
 *
 * usage: icp-anchors.mjs [--all] [--file bundle.pem] [--dry-run]
 * env:   CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, KV_NAMESPACE_ID
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const all = args.includes("--all");
const dryRun = args.includes("--dry-run");
const fileIdx = args.indexOf("--file");
const file = fileIdx >= 0 ? args[fileIdx + 1] : null;

const ROOTS = ["ICP-Brasilv2.crt", "ICP-Brasilv5.crt", "ICP-Brasilv10.crt", "ICP-Brasilv11.crt", "ICP-Brasilv12.crt"];
const ROOT_BASE = "https://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/";
const ALL_ZIP = "https://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip";

const toPem = (der) => `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
const isPem = (buf) => buf.toString("latin1").includes("-----BEGIN CERTIFICATE-----");

async function fetchBytes(url) {
  const r = await fetch(url, { headers: { "user-agent": "kya-brasil/anchors" } });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
}

let pems = [];
if (file) {
  const buf = readFileSync(file);
  pems = isPem(buf) ? [...buf.toString().matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)].map((m) => m[0] + "\n") : [toPem(buf)];
} else if (all) {
  const dir = mkdtempSync(join(tmpdir(), "icp-"));
  writeFileSync(join(dir, "ac.zip"), await fetchBytes(ALL_ZIP));
  execFileSync("unzip", ["-o", "-q", join(dir, "ac.zip"), "-d", join(dir, "out")]);
  for (const name of readdirSync(join(dir, "out")).filter((n) => /\.(crt|cer|pem)$/i.test(n)).sort()) {
    const buf = readFileSync(join(dir, "out", name));
    pems.push(isPem(buf) ? buf.toString() : toPem(buf));
  }
} else {
  for (const name of ROOTS) {
    try {
      const buf = await fetchBytes(ROOT_BASE + name);
      pems.push(isPem(buf) ? buf.toString() : toPem(buf));
      console.log("ok  ", name);
    } catch (e) {
      console.warn("skip", name, e.message);
    }
  }
}
pems = [...new Set(pems.map((p) => p.trim() + "\n"))];
if (!pems.length) {
  console.error("no certificates collected");
  process.exit(1);
}
const bundle = pems.join("");
console.log(`${pems.length} certificates, ${bundle.length} bytes`);
if (dryRun) {
  process.stdout.write(bundle);
  process.exit(0);
}

const { CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, KV_NAMESPACE_ID } = process.env;
if (!CLOUDFLARE_API_TOKEN || !CLOUDFLARE_ACCOUNT_ID || !KV_NAMESPACE_ID) {
  console.error("set CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, KV_NAMESPACE_ID (or use --dry-run)");
  process.exit(2);
}
const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces/${KV_NAMESPACE_ID}/values/icp:anchors`, {
  method: "PUT",
  headers: { authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`, "content-type": "text/plain" },
  body: bundle
});
if (!res.ok) {
  console.error("KV put failed", res.status, await res.text());
  process.exit(1);
}
console.log("uploaded icp:anchors");
