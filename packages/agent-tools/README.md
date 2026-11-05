# @kya-brasil/agent-tools

**Know-your-agent for Brazil, as code.** Verify that an AI agent really acts for a Brazilian company
(credential signed by the company's e-CNPJ, checked against its AC's revocation list, company active at the Receita Federal),
check an action against the agent's mandate, or give your own agent a credential.

Paid per call with [x402](https://x402.org) (USDC on Base, no signup). Free verification works without a wallet
(50/day per IP). Errors are never charged. MCP endpoint for agent frameworks: `https://kya-br-agents.marcelfons.workers.dev/mcp`.

```bash
npm i @kya-brasil/agent-tools
```

The same build is mirrored to GitHub Packages as `@celfons/kya-agent-tools` (listed on the repository page;
installing from there needs a GitHub token). npmjs.com is the channel to install from.

Node 18+ (global `fetch`, WebCrypto). ESM.

## Verifier: you receive an action from someone else's agent

```ts
import { createKyaClient, verifyAttestation, verifyCredentialOffline, companyText, signWithECnpj, hashPaymentRef } from "@kya-brasil/agent-tools";

const kya = createKyaClient({ privateKey: process.env.KYA_PAYER_PK as `0x${string}` }); // wallet optional

const v = await kya.verify(credentialId);                 // free
if (v.status !== "active") reject();

const verdict = await kya.allowed(credentialId, {         // $0.01, signed
  action: "order", amount: 4200, currency: "BRL", counterparty: "12345678000190"
});
if (!verdict.allowed) reject(verdict.reason);

await verifyAttestation(verdict);                          // local Ed25519 check of the issuer's signature

// max_per_day: pass your own spent_today; the issuer does not record acts.
// Payment instrument (card networks, acquirers, D-25): pass the hash of the token reference or PAR you received,
// never the card number: { payment_network: "visa", payment_ref_sha256: await hashPaymentRef(tokenRef) }

const offline = await verifyCredentialOffline(credential);   // issuer down: signature + expires_at only,
                                                             // live_status "unknown" (your risk until expires_at)
```

`verifyCredentialOffline` checks the attestation of an issuer: it does not apply to a self-issued credential
(`issuer: "urn:kya-brasil:self"`, D-37), which has none. For those use [offline mode](#verify-without-the-issuer-offline)
(`createKyaAuth({ offline, replayCache })`) or `verifySelfIssuedCredential` from `@kya-brasil/core`. A company
principal from the issuer has no `kind` field; only person credentials carry `kind: "person"`, so test for
`"person"`, not for `"company"`.

Also check that the key that signed the agent's request is `v.agent.id`; the credential_id alone proves nothing.

Company side, after issuance: see every agent in your name and get signed events (issued, renewed, suspended,
reinstated, revoked) at your webhook. Both requests are signed with the e-CNPJ:

```ts
const text = companyText("webhook", cnpj, { url: "https://acme.com.br/kya-events" });
await kya.setCompanyWebhook(cnpj, { signed_text: text, ecnpj_signature: await signWithECnpj(material, text) });
const inv = await kya.companyAgents(cnpj, { signed_text: t2, ecnpj_signature: s2 });   // t2 = companyText("agents", cnpj)
// on your webhook: (await verifyAttestation(body)).valid before trusting the event
```

Agent frameworks (verifier tools `kya_verify`, `kya_check_action`, `kya_verify_paid`):

```ts
import { toOpenAI, toVercelAI, toLangChain, toAnthropic } from "@kya-brasil/agent-tools";
toVercelAI(kya, { tool, jsonSchema });   // from "ai"
toLangChain(kya, tool);                  // from "@langchain/core/tools"
toOpenAI(kya); toAnthropic(kya);         // then kya.execute(name, args)
```

## Sign in with KYA: accept signed requests from agents

```ts
import { createKyaAuth } from "@kya-brasil/agent-tools";
const auth = createKyaAuth();                     // options: privateKey (for kya.allowed), cacheTtlMs, maxSkewSeconds

app.use("/api/*", auth.hono());                    // Hono: c.get("kya")
app.use(auth.express());                           // Express: req.kya
export default { fetch: auth.fetchHandler(async (req, kya) => Response.json({ hello: kya.principal.legal_name })) }; // Workers
const r = await auth.authenticate(request);        // anywhere: { ok, kya } or { ok: false, status, error, message }
```

`kya` carries `credential_id`, `agent`, `principal`, `mandate`, `check(q)` (local mandate evaluation, no daily
ceilings) and `allowed(q)` (the issuer's signed verdict, $0.01). The agent signs with `signRequest(...)`:

```ts
import { signRequest } from "@kya-brasil/agent-tools";
const headers = await signRequest({ credentialId, key: { kind: "evm", privateKey: agentPk }, method: "POST", url, body });
// headers: KYA-Credential, KYA-Created, KYA-Expires, KYA-Signature, and KYA-Content-SHA256 when there is a body
// (+ KYA-Delegation for a sub-agent, + KYA-Credential-Document and KYA-Principal-Proof with `present`)
await fetch(url, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });
```

Keys: `{ kind: "evm" | "erc8004", privateKey }` or `{ kind: "web-bot-auth", privateKey: CryptoKey | pkcs8 }`.

### Replay protection (opt-in)

Without a cache, a signed request can be sent again while its window is open (up to `maxTtlSeconds`, 600 s by
default). Pass a replay cache and each accepted request is remembered until its own `KYA-Expires`; the same request
again gets `401 KYA_REQUEST_REPLAYED`:

```ts
import { createKyaAuth, memoryReplayCache } from "@kya-brasil/agent-tools";
const auth = createKyaAuth({ replayCache: memoryReplayCache() });   // works with the offline option too
```

The key is the SHA-256 of the signed request text (credential, delegation, method, URL, created, expires, body
hash), recorded only after the request fully verified, so forged requests cannot fill the cache. Entries live
until the request expires, never less (a shorter memory lets a replay through; see `docs/formal/threats.als`), and
`maxTtlSeconds` must be finite. `memoryReplayCache()` serves one process (`maxEntries`, default 100 000; when full
of live entries it refuses rather than forgets). With several instances, implement `ReplayCache.seen(key,
expiresAt, now)` on a shared store that records atomically (Redis `SET key 1 NX PXAT expiresAt`, a unique key in
a database); a store error answers `502 KYA_REPLAY_CACHE_UNAVAILABLE`. An agent that sends two identical requests
in the same second must vary them (any body or query difference), or the second is refused as a replay.

### Agent to agent (mutual)

The callee signs its response, bound to the request; the caller verifies who answered.

```ts
import { createKyaAgent, signResponse } from "@kya-brasil/agent-tools";

// callee (inside a handler, after auth.authenticate succeeded)
const headers = await signResponse({ credentialId: myCredentialId, key: myKey, requestSignature: request.headers.get("kya-signature")!, body });
return new Response(body, { headers: { ...headers, "content-type": "application/json" } });

// caller
const me = createKyaAgent({ credentialId: myCredentialId, key: myKey });
const { response, callee } = await me.fetch("https://beta.com.br/orders", { method: "POST", body });
if (!callee?.ok) throw new Error("unsigned or invalid callee");       // callee.kya: principal, mandate, status
```

### Sub-agents (delegation, D-30): one certificate signature for the whole tree

When the mandate carries `delegation: { max_depth, max_ttl_seconds }`, the agent hands a narrower mandate to
another key with its own signature, no new e-CNPJ or e-CPF signature. The sub-agent signs its requests with its own
key and sends the chain; your middleware verifies it offline and `check()` / `allowed()` evaluate every mandate in it.

```ts
import { signDelegation, signRequest } from "@kya-brasil/agent-tools";
const chain = await signDelegation({ credential, key: agentKey, delegate: { kind: "web-bot-auth", id: subPublicKey },
  mandate: { actions: ["quote"], max_per_operation: { amount: 500, currency: "BRL" } }, ttlSeconds: 600 });
const headers = await signRequest({ credentialId, key: subKey, delegation: chain, method: "GET", url });
// server side: c.get("kya").delegation → { depth, delegate, mandates, expires_at, chain }
```

Short-lived (at most `max_ttl_seconds`, never past the credential), contained in the parent mandate, at most 3
levels; revoking the credential ends the whole tree. The issuer stores nothing. [SPEC](https://github.com/celfons/kya-brasil/blob/main/docs/SPEC.md) section 17.

### Verify without the issuer (offline)

Opt-in. The agent sends its credential and the principal's proof with the request; the middleware checks them
against ICP-Brasil alone and never calls the issuer (or any network: the certificate's status is your callback).
Works with self-issued credentials (`issuer: "urn:kya-brasil:self"`, issued with `@kya-brasil/core`'s
`assembleCredential`) and with credentials from an issuer whose public key you list.

```ts
import { createKyaAuth, memoryReplayCache, signRequest } from "@kya-brasil/agent-tools";
import { evidenceFromRevocation, verifyCrl, type VerifiedCrl } from "@kya-brasil/core";

// agent: credential and proof as assembleCredential returned them (or the issuer's credential + your .p7s proof)
const headers = await signRequest({ credentialId, key, method: "POST", url, body, present: { credential, proof } });

// server: one clock for everything (the same function goes to createKyaAuth below), so the CRL cache, the CRL's
// validity and the request window all agree, including under a test or simulated clock
const now = () => new Date();
// the certificate's CRL, fetched from crl_urls, verified against the AC and cached until its nextUpdate
const crls = new Map<string, VerifiedCrl>();
async function certificateStatus({ revocation }: CertificateStatusQuery) {
  const url = revocation.crl_urls[0];
  if (!url || !revocation.issuer_certificate) throw new Error("no CRL or AC certificate"); // -> 502, fail closed
  const at = now();
  let crl = crls.get(url);
  if (!crl || (crl.next_update && Date.parse(crl.next_update) <= at.getTime())) {
    const crlDer = new Uint8Array(await (await fetch(url)).arrayBuffer());
    crl = await verifyCrl({ crlDer, issuerCertificate: revocation.issuer_certificate, pastNextUpdate: "refuse", now: at });
    crls.set(url, crl);
  }
  return evidenceFromRevocation(crl.lookup(revocation.serial_number), url);
}

// nothing has a default; construction throws without anchors, now or certificateStatus
const auth = createKyaAuth({
  replayCache: memoryReplayCache(),                  // see "Replay protection"
  offline: {
    anchors: icpBrasilAnchors,                       // string[]: PEM blocks or base64 DER, see "Trust anchors" below
    now,                                             // your clock, the same one certificateStatus uses
    certificateStatus,
    // freshness: { ... },                         // optional, SPEC section 18 (freshnessPolicy): check() also runs checkFreshAction
    issuerKeys: { "https://kya-br-agents.marcelfons.workers.dev": issuerJwk }, // optional; others are refused
    issuerFallback: false                            // optional: true sends requests without the credential to the issuer
  }
});
```

(`CertificateStatusQuery` is a type exported by this package. `checkRevocation({ crlDer, serial, issuerCertificate,
pastNextUpdate, now })` is the one-shot form of `verifyCrl(...).lookup(serial)`.) A runnable version, with a test PKI
and its CRL, is in [examples/quickstart](https://github.com/celfons/kya-brasil/tree/main/examples/quickstart).

**Trust anchors.** `anchors` is an array of strings, each one certificate as a PEM block or as base64 DER. The
ICP-Brasil bundle (roots and intermediate ACs, from the ITI) is `anchors/icp-brasil.pem` in the repository; it is
not in the npm package. Fetch it from a pinned commit, not from `main`, and review changes to it like code:
`https://raw.githubusercontent.com/celfons/kya-brasil/<commit>/anchors/icp-brasil.pem`. Split it into blocks with
`pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)`.

**Header size.** `KYA-Principal-Proof` carries the signed text and the full CMS, certificate chain included: about
4 to 6 KB with the e-CNPJ alone and about 8.5 KB with one e-CPF co-signature (up to 12 KB when each CMS carries a
three-certificate chain), plus about 2 KB of `KYA-Credential-Document`. Many proxies and servers limit request headers to 8 KB per header or 8 to 16 KB in total
(nginx `large_client_header_buffers`, Node `--max-http-header-size`, 16 KB by default, cloud load balancers): raise
the limit on the verifier's path. SPEC section 19 also allows the same `{ text, cms }` object in the request body;
the middleware reads only the header, so a verifier that takes it from the body decodes it itself
(`decodePrincipalProofHeader`) and calls `verifySelfIssuedCredential` / `verifyPrincipalProof`.

Headers: `KYA-Credential-Document` (base64url of the credential's JSON) and `KYA-Principal-Proof`, plus
`KYA-Delegation` for a sub-agent. The middleware verifies the request signature (agent or last delegate), the
proof (`verifySelfIssuedCredential`, or `verifyPrincipalProof` and the issuer's attestation), the delegation
chain at your clock, and the certificate's status; `kya.offline` holds the evidence, and `check()` / `allowed()`
evaluate every mandate locally (`allowed()` returns an unsigned local verdict). New errors:
`KYA_CREDENTIAL_MISSING`, `KYA_CREDENTIAL_MALFORMED`, `KYA_CREDENTIAL_MISMATCH`, `KYA_PRINCIPAL_PROOF_MISSING`,
`KYA_PRINCIPAL_PROOF_MALFORMED`, `KYA_PRINCIPAL_PROOF_INVALID`, `KYA_ISSUER_NOT_TRUSTED`,
`KYA_CREDENTIAL_SIGNATURE_INVALID`, `KYA_CERTIFICATE_REVOKED`, `KYA_CERTIFICATE_STATUS_UNKNOWN`,
`KYA_CERTIFICATE_STATUS_STALE` (403), `KYA_CERTIFICATE_STATUS_UNAVAILABLE` (502), `KYA_CLOCK_INVALID` (502).
What it cannot see: a revocation or suspension made only at an issuer; daily ceilings need your `spent_today`.
The headers carry the principal's certificate (personal data for an e-CPF): treat them as such.

## Person: an agent that acts for you (e-CPF)

```ts
const reg = await kya.register({ agent: { kind: "evm", id: agentAddress }, principal: "person", mandate }); // $0.25
// agent signs reg.challenge.text; you sign it with your e-CPF (reg.sign_url, kya-sign or signWithECnpjPfx: same code)
const { credential } = await kya.prove(reg.credential_id, { challenge_id: reg.challenge.id, agent_signature, ecnpj_signature: ecpfSignature });
// credential.principal = { kind: "person", verified_by: "icp-brasil-e-cpf" }: nothing personal

// A verifier that already has the person's CPF:
const m = await kya.principalMatch(credentialId, "529.982.247-25");   // $0.01, signed: { match, subject_ref? }

// The person, to see their agents and every check made on them:
const text = personAgentsText();                                        // import { personAgentsText }; sign it with the e-CPF
const mine = await kya.personAgents({ signed_text: text, ecpf_signature });
```

## Company: give your own agent a credential

```ts
import { createKyaClient, signChallengeWithEvmKey, signingLink, signWithECnpjPfx } from "@kya-brasil/agent-tools";
import { readFileSync } from "node:fs";

const kya = createKyaClient({ privateKey: payerPk });
const reg = await kya.register({                                           // $0.25
  agent: { kind: "evm", id: agentAddress },
  cnpj: "11.222.333/0001-81",
  mandate: {
    actions: ["quote", "order", "pay"],
    max_per_operation: { amount: 5000, currency: "BRL" },
    max_per_day: { amount: 20000, currency: "BRL" },
    currencies: ["BRL"],
    counterparties: ["12345678000190", "*.beta.com.br"]
  }
});

const agent_signature = await signChallengeWithEvmKey(agentPk, reg.challenge.text);

// Usual case: a person holds the e-CNPJ (owner, accountant). Send them the link; they sign in the browser
// (.pfx, or a .p7s from any ICP-Brasil signer for A3 tokens and cloud certificates) and the credential is issued.
const link = signingLink({ credentialId: reg.credential_id, challenge: reg.challenge, agentSignature: agent_signature });
// (reg.sign_url is the same link without the agent signature)

// Or in code, when you hold the A1 file yourself:
const ecnpj_signature = await signWithECnpjPfx(readFileSync("empresa.pfx"), process.env.PFX_PASSWORD!, reg.challenge.text);
const { credential, warnings } = await kya.prove(reg.credential_id, { challenge_id: reg.challenge.id, agent_signature, ecnpj_signature }); // free
```

`signWithECnpjPfx` reads the `.pfx`/`.p12` directly, including the legacy 3DES/RC2 encryption many Brazilian A1
files use; `signWithECnpj` still takes PEM. On a terminal, the `kya-sign` command does the same without code:

```sh
npx -p @kya-brasil/agent-tools kya-sign --pfx empresa.pfx --link "<sign_url>&agent_signature=…"   # signs and issues
npx -p @kya-brasil/agent-tools kya-sign --pfx empresa.pfx --text-file desafio.txt               # prints the signature
```

The password comes from `KYA_PFX_PASSWORD` or is asked for without echo. Everything runs locally.

**A3 (token or smart card).** Through PKCS#11, the interface every ICP-Brasil token driver ships. Install the
optional `pkcs11js` and point to the vendor's library (e.g. SafeNet eToken `libeTPkcs11.so` / `eTPKCS11.dll`):

```sh
npm install pkcs11js
npx -p @kya-brasil/agent-tools kya-sign --pkcs11 /usr/lib/libeTPkcs11.so --list                       # certificates on the token
npx -p @kya-brasil/agent-tools kya-sign --pkcs11 /usr/lib/libeTPkcs11.so --link "<sign_url>&agent_signature=…"
```

```ts
import { openToken } from "@kya-brasil/agent-tools";
let ecnpj_signature: string;
const token = await openToken({ library: "/usr/lib/libeTPkcs11.so", pin: process.env.TOKEN_PIN! });
try { ecnpj_signature = await token.sign(reg.challenge.text); } finally { token.close(); }
```

The PIN comes from `KYA_TOKEN_PIN` or is asked for. The key never leaves the token. Tested against SoftHSM2 (a
software PKCS#11 token) in CI. The signing code is in `@kya-brasil/core` (`openPfx`, `ecnpjSigner`,
`buildDetachedCms`), re-exported here; any other token or cloud signer plugs into `ecnpjSigner`.

**Issue the credential yourself, no service (D-37).** With the token (or `--pfx` / `--cloud`), the holder issues a
self-issued credential (`issuer: urn:kya-brasil:self`) from a mandate input file (`MandateInput` of
`@kya-brasil/core`: `credential_id`, `agent`, `principal`, every risk field of `mandate`, `ttl_seconds`; `now`
optional, default the current clock). `--anchors` is the ICP-Brasil bundle (PEM) the result is checked against.
A legal representative then co-signs with their e-CPF (SPEC section 21; on a token, the e-CPF certificate is picked
unless `--label` says otherwise), so a verifier can check that the company, not only whoever holds its e-CNPJ, wants
the mandate (`verifyCompanyWill` in the core):

```sh
npx -p @kya-brasil/agent-tools kya-sign --pkcs11 /usr/lib/libeTPkcs11.so --issue mandate-input.json --anchors icp-brasil.pem --out credential.json
npx -p @kya-brasil/agent-tools kya-sign --pkcs11 /usr/lib/libeTPkcs11.so --cosign credential.json --anchors icp-brasil.pem --out credential.json   # e-CPF of a representative
```

A sample input is [examples/quickstart/mandate-input.json](https://github.com/celfons/kya-brasil/blob/main/examples/quickstart/mandate-input.json):
every risk field is required (`[]` means "any", `delegation: null` means "may not delegate"). **`--cosign` without
`--out` overwrites the input file** with the co-signed credential; pass `--out` to keep the original. Anchors: see
[Trust anchors](#verify-without-the-issuer-offline).

`credential.json` holds `{ credential, proof }`: hand both to the agent. The text signed is printed before signing.
Check the certificate's CRL before using the credential (the command does not go online).

**Cloud certificate (PSC).** `kya-sign --cloud ./my-psc.mjs --link "<sign_url>"` with a module that implements
`CloudSignatureProvider` for your PSC ([template](https://github.com/celfons/kya-brasil/tree/main/examples/cloud-provider));
the browser opens for the approval and the terminal receives the redirect on `127.0.0.1`.

**From the agent's side**, `kya.signLink(credentialId, { challenge_id, agent_signature })` (free) returns the
`sign_url` to send, the same as `signingLink(...)` offline and the MCP tool `kya_sign_link`.

An agent should not hold the company's e-CNPJ to sign for itself: that signature is the company's consent.
Let the agent prepare and send the link, and a person sign.

Renew every 90 days (`kya.renew` then `kya.renewProve`), revoke at once (`kya.revoke` with `revocationText(id)` signed by the e-CNPJ).

## Prices (USDC)

| Call | Price |
|---|---|
| verify, verifyByKey, prove, renewProve, revoke, revocations, companyAgents, setCompanyWebhook | free |
| verified (signed receipt, no limit), allowed (signed verdict) | 0.01 |
| renew | 0.10 |
| register | 0.25 |

Schemas and keys: `/.well-known/kya-mandate.schema.json`, `/.well-known/kya.json`, `/openapi.json`, `/llms.txt`.
What the issuer stores: for a company, no CPF or name of the e-CNPJ holder (recorded by certificate hash only); for
a person (D-29), only a keyed HMAC of the CPF, never the name or the CPF, deleted when the credential is revoked or
expires.
