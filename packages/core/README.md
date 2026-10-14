# @kya-brasil/core

KYA Brasil as a library. Verify, or issue, know-your-agent credentials for Brazilian companies inside your own
systems, with no hosted service in the path: the same code the reference issuer runs, as pure functions.

- **e-CNPJ (ICP-Brasil)**: CMS/PKCS#7 signature validation, chain up to the ICP-Brasil roots, CNPJ read from the certificate.
- **Revocation**: CRL verification against the issuing AC and the effect on a credential (revoke, suspend, nothing).
- **Agent keys**: challenge text and signature checks for EVM wallets (EIP-191), Ed25519 (Web Bot Auth, RFC 9421) and ERC-8004 agents.
- **Mandate**: schema, validation and deterministic evaluation of an intended action, including **payment instruments** for card networks, acquirers and issuers.
- **Credential**: build, sign and verify (Ed25519 over canonical JSON), offline.
- **CNPJ**: normalize, validate, format.

Storage, network calls and keys stay yours: the library never fetches anything except an ERC-8004 lookup over
the RPC transport you give it. Spec: [docs/SPEC.md](https://github.com/celfons/kya-brasil/blob/main/docs/SPEC.md).

```sh
npm install @kya-brasil/core
```

ESM, Node 18+, Workers, Deno and browsers (Web Crypto).

## Verify a credential and an action, offline

A credential from any KYA issuer (the hosted one, yours, a partner's) is checked with that issuer's public key,
published at `<issuer>/.well-known/kya.json`.

```ts
import { verifyCredentialSignature, effectiveStatus, checkAction, hashPaymentRef } from "@kya-brasil/core";

const sig = await verifyCredentialSignature(credential, issuerPublicJwk); // { valid, key_id, signed_at }
if (!sig.valid || effectiveStatus(credential) !== "active") deny();
// For live status (revoked or suspended after issuance) read credential.verify_url, or accept that risk until expires_at.

const verdict = checkAction(credential.mandate, {
  action: "buy",
  amount: 4200,
  currency: "BRL",
  counterparty: "33000167000101",
  spent_today: 9000,                                   // your own count; nobody else keeps it
  payment_network: "visa",
  payment_ref_sha256: await hashPaymentRef(tokenRef)   // the network token reference or PAR of this transaction
});
// verdict.allowed, verdict.checks (every rule evaluated, with its reason), verdict.not_evaluated (extensions)
```

## Delegation chains (sub-agents)

A mandate with `delegation: { max_depth, max_ttl_seconds }` lets the agent hand a narrower mandate to another key
(SPEC section 17). Verify a chain received in `KYA-Delegation`, offline, then evaluate the action on every level:

```ts
import { checkDelegatedAction, decodeDelegationHeader, verifyDelegationChain } from "@kya-brasil/core";
const r = await verifyDelegationChain({ credential, chain: decodeDelegationHeader(header) });
if (!r.ok) reject(r.error);                         // r.delegate is the key that must sign the request
const verdict = checkDelegatedAction(r.mandates, { action: "quote", amount: 80, currency: "BRL" });
```

To delegate, `prepareDelegation({ credential, chain, delegate, mandate, ttlSeconds })` returns the delegation and
the text the delegator signs with its agent key; `mandateSubsetProblems(parent, child)` says why a mandate is broader.

## Payment instruments (card networks, acquirers, issuers)

A mandate can list the instruments the agent may pay with. Each one is a network and the SHA-256 of a reference
the network already gives (network token reference, Payment Account Reference), **never a card number**:

```json
{
  "actions": ["buy"],
  "max_per_operation": { "amount": 5000, "currency": "BRL" },
  "payment_instruments": [
    { "network": "visa", "ref_sha256": "9f2c…", "label": "purchasing" },
    { "network": "mastercard", "ref_sha256": "a71b…" }
  ]
}
```

- `ref_sha256` = lowercase hex SHA-256 of the reference, UTF-8, whitespace removed, case kept. `hashPaymentRef(ref)` does exactly that.
- `validateMandate` refuses anything that is not a 64-hex hash, labels containing long digit runs, unknown fields and duplicates, so a PAN cannot slip into a credential.
- At authorization time, hash the reference you received and pass it to `checkAction`: the verdict says whether that instrument belongs to an agent the company (CNPJ, e-CNPJ-signed) authorized, within its limits. When the mandate has no list, or you pass no reference, the rule is not evaluated.

With the hosted issuer, the same check comes back signed from
`GET /v1/agents/{id}/allowed?payment_network=visa&payment_ref_sha256=…`, which is evidence for a later dispute.

## Sign as the e-CNPJ holder (A1 and A3)

The company's side of the challenge, without the hosted page. The issuer only ever receives the signature.

```ts
import { openPfx, ecnpjSigner, readSigningLink } from "@kya-brasil/core";

// A1: the .pfx / .p12 file (legacy 3DES/RC2 PKCS#12 included)
const a1 = await openPfx(pfxBytes, password);
const ecnpj_signature = await a1.sign(challengeText);       // detached CMS, base64: POST it to /v1/agents/{id}/prove

// A3 token, smart card, HSM or cloud certificate: anything that signs bytes with the certificate's RSA key
// (PKCS#1 v1.5 over SHA-256), plus the certificate chain in DER.
const a3 = ecnpjSigner({ certificates: [certDer, ...chainDer], sign: (bytes) => myToken.sign("SHA256withRSA", bytes) });
const sig = await a3.sign(readSigningLink(link).text);       // the text from a /sign link the agent sent
```

`sign` refuses a text whose `cnpj:` line names another company. For PKCS#11 tokens on Node,
`openToken({ library, pin })` in `@kya-brasil/agent-tools` (and the `kya-sign --pkcs11` command) already wires
`C_Sign` into `ecnpjSigner`.

### Cloud certificates (PSC)

`CloudSignatureProvider` is the interface for an e-CNPJ held by an ICP-Brasil PSC: `authorizationUrl` (OAuth with
PKCE), `exchangeCode` returning a session with `certificates()` and `signHash(sha256)`. No PSC is implemented here
(each has its own contract); implement it for yours from
[examples/cloud-provider](https://github.com/celfons/kya-brasil/tree/main/examples/cloud-provider) and then:

```ts
import { cloudSigner, pkcePair, newState } from "@kya-brasil/core";
const { verifier, challenge } = await pkcePair();
const url = await provider.authorizationUrl({ redirectUri, state: newState(), codeChallenge: challenge });
// … the person approves, your redirect URI gets ?code=…&state=…
const signer = await cloudSigner(await provider.exchangeCode({ code, redirectUri, codeVerifier: verifier }));
const ecnpj_signature = await signer.sign(challengeText);
```

## Run your own issuer

```ts
import {
  newChallenge, verifyAgentSignature, verifyIcpSignature, checkRevocation,
  validateMandate, buildCredential, signCredential, importPrivateKey, generateAttestationKey
} from "@kya-brasil/core";

const key = await generateAttestationKey();               // once; keep privateKeyPkcs8 secret, publish publicJwk
const ch = newChallenge({ issuer: "https://kya.acquirer.example", agent, cnpj });
// The agent signs ch.text with its key; the company signs ch.text with its e-CNPJ (detached CMS).
if (!(await verifyAgentSignature(agent, ch.text, agentSignature))) throw new Error("agent signature");
const icp = await verifyIcpSignature({ cmsBase64: ecnpjSignature, challenge: ch.text, expectedCnpj: cnpj, anchors });
// anchors: the ICP-Brasil roots as PEM strings (bundle in the repository: anchors/icp-brasil.pem).
const crlDer = await fetchCrl(icp.crl_urls);             // yours: HTTP + cache
const rev = await checkRevocation({ crlDer, serial: icp.serial_number, issuerCertificate: icp.issuer_certificate! });
if (rev.revoked) throw new Error("certificate revoked");

const credential = await signCredential(
  buildCredential({
    credential_id: crypto.randomUUID(), agent, cnpj,
    legal_name, registration_status,                      // from your registration source; "UNVERIFIED" if none answered
    certificate: { sha256: icp.certificate_sha256, subject: icp.certificate_subject, issuer: icp.issuer, signed_at: icp.signed_at },
    mandate: validateMandate(mandate),
    issuer: "https://kya.acquirer.example"
  }),
  await importPrivateKey(key.privateKeyPkcs8), key.keyId
);
```

What the library leaves to you: persistence, the challenge's single use and expiry, fetching and caching CRLs,
the company's registration status (the reference issuer reads the Receita's open data), key custody and the
publication of your public key. `apps/worker` in the repository is a complete issuer built this way.

## Compatibility

Credentials follow `/v1` of the spec: fields are only ever added. Test vectors:
[docs/vectors/credential-v1.json](https://github.com/celfons/kya-brasil/blob/main/docs/vectors/credential-v1.json).

MIT. Issues and contributions: https://github.com/celfons/kya-brasil
