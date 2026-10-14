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
await fetch(url, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });
```

Keys: `{ kind: "evm" | "erc8004", privateKey }` or `{ kind: "web-bot-auth", privateKey: CryptoKey | pkcs8 }`.

### Agent to agent (mutual)

The callee signs its response, bound to the request; the caller verifies who answered.

```ts
// callee (inside a handler, after auth.authenticate succeeded)
const headers = await signResponse({ credentialId: myCredentialId, key: myKey, requestSignature: request.headers.get("kya-signature")!, body });
return new Response(body, { headers: { ...headers, "content-type": "application/json" } });

// caller
const me = createKyaAgent({ credentialId: myCredentialId, key: myKey });
const { response, callee } = await me.fetch("https://beta.com.br/orders", { method: "POST", body });
if (!callee?.ok) throw new Error("unsigned or invalid callee");       // callee.kya: principal, mandate, status
```

## Person: an agent that acts for you (e-CPF)

```ts
const reg = await kya.register({ agent: { kind: "evm", id: agentAddress }, principal: "person", mandate }); // $0.25
// agent signs reg.challenge.text; you sign it with your e-CPF (reg.sign_url, kya-sign or signWithECnpjPfx: same code)
const { credential } = await kya.prove(reg.credential_id, { challenge_id: reg.challenge.id, agent_signature, ecnpj_signature: ecpfSignature });
// credential.principal = { kind: "person", verified_by: "icp-brasil-e-cpf" }: nothing personal

// A verifier that already has the person's CPF:
const m = await kya.principalMatch(credentialId, "529.982.247-25");   // $0.01, signed: { match, subject_ref? }

// The person, to see their agents and every check made on them:
const text = personAgentsText();                                        // sign it with the e-CPF
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
const ecnpj_signature = signWithECnpjPfx(readFileSync("empresa.pfx"), process.env.PFX_PASSWORD!, reg.challenge.text);
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
const token = await openToken({ library: "/usr/lib/libeTPkcs11.so", pin: process.env.TOKEN_PIN! });
try { ecnpj_signature = await token.sign(reg.challenge.text); } finally { token.close(); }
```

The PIN comes from `KYA_TOKEN_PIN` or is asked for. The key never leaves the token. Tested against SoftHSM2 (a
software PKCS#11 token) in CI. The signing code is in `@kya-brasil/core` (`openPfx`, `ecnpjSigner`,
`buildDetachedCms`), re-exported here; any other token or cloud signer plugs into `ecnpjSigner`.

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
Legal entities only: no CPF is stored; the e-CNPJ signer is recorded by certificate hash.
