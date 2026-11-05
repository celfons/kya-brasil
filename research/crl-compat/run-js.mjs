// @peculiar/x509, PKI.js, node-forge and @kya-brasil/core: parse and verify every CRL in data/pairs.json.
// Prints JSON lines. Usage: tsx run-js.mjs data/pairs.json
import "reflect-metadata";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";
import * as x509 from "@peculiar/x509";
import * as pkijs from "pkijs";
import forge from "node-forge";
import { verifyCrl } from "@kya-brasil/core";

const require = createRequire(import.meta.url);
const version = (name) => {
  try {
    return require(`${name}/package.json`).version;
  } catch {
    return JSON.parse(readFileSync(new URL(`node_modules/${name}/package.json`, import.meta.url), "utf8")).version; // "exports" hides it
  }
};
x509.cryptoProvider.set(globalThis.crypto);
pkijs.setEngine("webcrypto", new pkijs.CryptoEngine({ name: "webcrypto", crypto: globalThis.crypto }));

const pemToDer = (pem) => Buffer.from(pem.replace(/-----[^-]+-----|\s+/g, ""), "base64");
const ab = (u) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength);
const msg = (e) => `${e?.name ?? "Error"}: ${e?.message ?? e}`.slice(0, 200);

async function median(fn) {
  const ms = [];
  let out;
  for (let i = 0; i < 3; i++) {
    const t0 = performance.now();
    out = await fn();
    ms.push(performance.now() - t0);
  }
  ms.sort((a, b) => a - b);
  return [out, ms[1]];
}

/** Each library: parse(der) throws on failure; verify(der, certPem) resolves true/false or throws. */
const libs = [
  {
    lib: "@peculiar/x509", version: version("@peculiar/x509"),
    parse: (der) => new x509.X509Crl(der),
    verify: (der, pem) => new x509.X509Crl(der).verify({ publicKey: new x509.X509Certificate(pemToDer(pem)) })
  },
  {
    lib: "PKI.js", version: version("pkijs"),
    parse: (der) => pkijs.CertificateRevocationList.fromBER(ab(der)),
    verify: (der, pem) => pkijs.CertificateRevocationList.fromBER(ab(der)).verify({ issuerCertificate: pkijs.Certificate.fromBER(ab(pemToDer(pem))) })
  },
  {
    lib: "node-forge", version: version("node-forge"),
    parse: () => {
      if (!Object.keys(forge.pki).some((k) => /crl/i.test(k))) throw new Error("node-forge has no CRL API (forge.pki)");
    },
    verify: () => false
  },
  {
    lib: "@kya-brasil/core", version: version("@kya-brasil/core"),
    parse: () => {},
    verify: async (der, pem) => {
      await verifyCrl({ crlDer: der, issuerCertificate: pem, pastNextUpdate: "accept" });
      return true;
    }
  }
];

const pairs = JSON.parse(readFileSync(process.argv[2], "utf8")).pairs;
for (const L of libs) {
  for (const p of pairs) {
    const der = new Uint8Array(readFileSync(p.crl));
    const r = { lib: L.lib, version: L.version, id: p.id, outcome: "", detail: "", ms: null };
    try {
      L.parse(der);
    } catch (e) {
      Object.assign(r, { outcome: "parse_error", detail: msg(e) });
      console.log(JSON.stringify(r));
      continue;
    }
    if (!p.issuers.length) {
      r.outcome = "parsed_no_issuer";
      console.log(JSON.stringify(r));
      continue;
    }
    let last = "";
    for (const cert of p.issuers) {
      const pem = readFileSync(cert, "utf8");
      try {
        const [ok, ms] = await median(() => L.verify(der, pem));
        if (ok) {
          Object.assign(r, { outcome: "ok", ms });
          break;
        }
        last = "verify returned false";
      } catch (e) {
        last = msg(e);
      }
    }
    if (!r.outcome) Object.assign(r, { outcome: "verify_failed", detail: last });
    console.log(JSON.stringify(r));
  }
}
