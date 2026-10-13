# @kya-brasil/agent-tools

**Know-your-agent for Brazil, as code.** Verify that an AI agent really acts for a Brazilian company
(credential signed by the company's e-CNPJ, checked against its AC's revocation list, company active at the Receita Federal),
check an action against the agent's mandate, or give your own agent a credential.

Paid per call with [x402](https://x402.org) (USDC on Base, no signup). Free verification works without a wallet
(50/day per IP). Errors are never charged. MCP endpoint for agent frameworks: `https://kya-br-agents.marcelfons.workers.dev/mcp`.

```bash
npm i @kya-brasil/agent-tools
```

Node 18+ (global `fetch`, WebCrypto). ESM.

## Verifier: you receive an action from someone else's agent

```ts
import { createKyaClient, verifyAttestation } from "@kya-brasil/agent-tools";

const kya = createKyaClient({ privateKey: process.env.KYA_PAYER_PK as `0x${string}` }); // wallet optional

const v = await kya.verify(credentialId);                 // free
if (v.status !== "active") reject();

const verdict = await kya.allowed(credentialId, {         // $0.01, signed
  action: "order", amount: 4200, currency: "BRL", counterparty: "12345678000190"
});
if (!verdict.allowed) reject(verdict.reason);

await verifyAttestation(verdict);                          // local Ed25519 check of the issuer's signature

const receipt = await kya.registerAct(credentialId, {       // $0.02 once you accept it: signed receipt,
  action: "order", amount: 4200, currency: "BRL", counterparty: "12345678000190", reference: "PO-1"
});                                                          // daily ceilings enforced across counterparties
```

Also check that the key that signed the agent's request is `v.agent.id`; the credential_id alone proves nothing.

Agent frameworks (verifier tools `kya_verify`, `kya_check_action`, `kya_register_act`, `kya_verify_paid`):

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

## Company: give your own agent a credential

```ts
import { createKyaClient, signChallengeWithEvmKey, signWithECnpj } from "@kya-brasil/agent-tools";
import { readFileSync } from "node:fs";

const kya = createKyaClient({ privateKey: payerPk });
const reg = await kya.register({                                           // $0.50
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
const ecnpj_signature = await signWithECnpj({
  certificatePem: readFileSync("ecnpj.crt.pem", "utf8"),
  privateKeyPem: readFileSync("ecnpj.key.pem", "utf8"),
  chainPem: [readFileSync("ecnpj.chain.pem", "utf8")]
}, reg.challenge.text);

const { credential } = await kya.prove(reg.credential_id, { challenge_id: reg.challenge.id, agent_signature, ecnpj_signature }); // free
```

From an A1 `.pfx`: `openssl pkcs12 -in cert.pfx -clcerts -nokeys > ecnpj.crt.pem`,
`openssl pkcs12 -in cert.pfx -nocerts -nodes | openssl pkcs8 -topk8 -nocrypt > ecnpj.key.pem`,
`openssl pkcs12 -in cert.pfx -cacerts -nokeys > ecnpj.chain.pem`. A3 certificates (token, card) sign through the vendor's software;
pass the resulting detached CMS as `ecnpj_signature`.

Renew every 90 days (`kya.renew` then `kya.renewProve`), revoke at once (`kya.revoke` with `revocationText(id)` signed by the e-CNPJ).

## Prices (USDC)

| Call | Price |
|---|---|
| verify, verifyByKey, prove, renewProve, revoke, revocations | free |
| verified (signed receipt, no limit), allowed (signed verdict) | 0.01 |
| registerAct (signed receipt of what the agent did) | 0.02 |
| renew | 0.10 |
| register | 0.50 |

Schemas and keys: `/.well-known/kya-mandate.schema.json`, `/.well-known/kya.json`, `/openapi.json`, `/llms.txt`.
Legal entities only: no CPF is stored; the e-CNPJ signer is recorded by certificate hash.
