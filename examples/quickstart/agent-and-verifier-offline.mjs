// TEST ONLY: uses the worthless PKI from make-test-pki.mjs and the credential from self-issue.mjs. Run those first.
//
// The agent signs a request with signRequest(... present ...) and the verifier checks it with createKyaAuth({ offline,
// replayCache }): no issuer, no network. The verifier's certificateStatus reads the AC's CRL (here a local file; in
// production fetched from revocation.crl_urls), verifies it with verifyCrl and caches it until its nextUpdate.
// Expected: R$ 100 allowed, R$ 6.000 refused (above max_per_operation), the same request replayed refused.
// Exits non-zero on anything unexpected.
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createKyaAuth, memoryReplayCache, signRequest } from "@kya-brasil/agent-tools";
import { evidenceFromRevocation, verifyCrl } from "@kya-brasil/core";

const OUT = resolve(process.env.KYA_QUICKSTART_OUT ?? join(import.meta.dirname, "out"));
const read = (f) => readFileSync(join(OUT, f));
const fail = (why, detail) => {
  console.error(`FAIL: ${why}`, detail === undefined ? "" : JSON.stringify(detail, null, 2));
  process.exit(1);
};

const { credential, proof } = JSON.parse(read("credential.json"));
const agent = JSON.parse(read("agent.json"));
const anchors = read("anchors.pem").toString().match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);

// ---- verifier ----------------------------------------------------------------------------------------------
// CRL cache keyed by URL, kept until the CRL's nextUpdate. fetchCrl stands in for `fetch(url)` (crl_urls of the
// certificate); the test PKI's URL is fake, so it reads out/ac.crl.
const crlCache = new Map();
let crlFetches = 0;
const fetchCrl = async (_url) => {
  crlFetches++;
  return new Uint8Array(read("ac.crl")); // production: new Uint8Array(await (await fetch(_url)).arrayBuffer())
};
async function certificateStatus({ revocation }) {
  if (!revocation.issuer_certificate) throw new Error("the issuing AC certificate is unknown: add it to the anchors");
  const url = revocation.crl_urls[0];
  if (!url) throw new Error("the certificate names no CRL");
  const now = new Date();
  let entry = crlCache.get(url);
  if (!entry || (entry.crl.next_update && Date.parse(entry.crl.next_update) <= now.getTime())) {
    const crl = await verifyCrl({ crlDer: await fetchCrl(url), issuerCertificate: revocation.issuer_certificate, pastNextUpdate: "refuse", now });
    entry = { crl };
    crlCache.set(url, entry);
  }
  // Throwing above answers 502 KYA_CERTIFICATE_STATUS_UNAVAILABLE (fail closed).
  return evidenceFromRevocation(entry.crl.lookup(revocation.serial_number), url);
}

const auth = createKyaAuth({
  replayCache: memoryReplayCache(), // multi-instance: a shared store (KV, Redis) implementing ReplayCache
  offline: { anchors, now: () => new Date(), certificateStatus }
});

// ---- agent -------------------------------------------------------------------------------------------------
const url = "https://fornecedor.example/api/pay";
const body = JSON.stringify({ amount: 100, currency: "BRL", to: "33000167000101" });
const headers = await signRequest({
  credentialId: credential.credential_id, key: { kind: "evm", privateKey: agent.privateKey },
  method: "POST", url, body, present: { credential, proof }
});
console.log(`agent sent ${Object.keys(headers).length} KYA headers: ${Object.keys(headers).join(", ")}`);
console.log(`KYA-Principal-Proof: ${headers["kya-principal-proof"].length} bytes, KYA-Credential-Document: ${headers["kya-credential-document"].length} bytes`);
const request = () => new Request(url, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });

// ---- verifier, per request ---------------------------------------------------------------------------------
const r = await auth.authenticate(request());
if (!r.ok) fail("a valid request was refused", r);
const { kya } = r;
if (!kya.offline?.self_issued) fail("expected an offline, self-issued verification", kya.offline);
console.log(`verified offline: agent ${kya.agent.id} for CNPJ ${kya.principal.cnpj}, body ${kya.body}`);

const ok = kya.check({ action: "pay", amount: 100, currency: "BRL", counterparty: "33000167000101" });
if (!ok.allowed) fail("R$ 100 to a listed counterparty should be allowed", ok);
console.log("R$ 100: allowed");

const tooMuch = kya.check({ action: "pay", amount: 6000, currency: "BRL", counterparty: "33000167000101" });
if (tooMuch.allowed) fail("R$ 6.000 is above max_per_operation and must be refused", tooMuch);
console.log(`R$ 6.000: refused (${tooMuch.checks.filter((c) => !c.ok).map((c) => c.rule).join(", ")})`);

const replay = await auth.authenticate(request());
if (replay.ok || replay.error !== "KYA_REQUEST_REPLAYED") fail("the replayed request must be refused with KYA_REQUEST_REPLAYED", replay);
console.log(`replay: refused (${replay.status} ${replay.error})`);

// A second, different request (signatures are deterministic: the same request in the same second IS a replay)
// reuses the cached CRL.
const body2 = JSON.stringify({ amount: 200, currency: "BRL", to: "33000167000101" });
const headers2 = await signRequest({ credentialId: credential.credential_id, key: { kind: "evm", privateKey: agent.privateKey }, method: "POST", url, body: body2, present: { credential, proof } });
const again = await auth.authenticate(new Request(url, { method: "POST", headers: { ...headers2, "content-type": "application/json" }, body: body2 }));
if (!again.ok) fail("a second fresh request was refused", again);
if (crlFetches !== 1) fail(`the CRL should be fetched once and cached until nextUpdate, fetched ${crlFetches} times`);
console.log("OK: offline verification, mandate ceiling, replay refusal and CRL cache all behave as expected");
