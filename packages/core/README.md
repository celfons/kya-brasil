# @kya-brasil/core

KYA Brasil as a library. Verify, or issue, know-your-agent credentials for Brazilian companies inside your own
systems, with no hosted service in the path: the same code the reference issuer runs, as pure functions.

- **e-CNPJ (ICP-Brasil)**: CMS/PKCS#7 signature validation, chain up to the ICP-Brasil roots, CNPJ read from the certificate.
- **Revocation**: CRL verification against the issuing AC and the effect on a credential (revoke, suspend, nothing).
- **Agent keys**: challenge text and signature checks for EVM wallets (EIP-191), Ed25519 (Web Bot Auth, RFC 9421) and ERC-8004 agents.
- **Mandate**: schema, validation and deterministic evaluation of an intended action, including **payment instruments** for card networks, acquirers and issuers.
- **Credential**: build, sign and verify (Ed25519 over canonical JSON, RFC 8785), offline.
- **Issuance by the principal**: the e-CNPJ / e-CPF holder issues the credential itself, with no issuer service: build the mandate, get the exact bytes to sign, assemble, and verify (`buildMandate`, `mandateSigningInput`, `assembleCredential`, `buildDelegation`).
- **CNPJ**: normalize, validate, format.

Storage, network calls and keys stay yours: the library never fetches anything except an ERC-8004 lookup over
the RPC transport you give it. Spec: [docs/SPEC.md](https://github.com/celfons/kya-brasil/blob/main/docs/SPEC.md).

```sh
npm install @kya-brasil/core
```

ESM, Node 18+, Workers, Deno and browsers (Web Crypto).

## Verify a credential and an action, offline

**Trust anchors.** Every function that checks an ICP-Brasil signature takes `anchors: string[]`, one certificate
per string, as a PEM block or base64 DER. The ICP-Brasil bundle (roots and intermediate ACs, from the ITI) is
[`anchors/icp-brasil.pem`](https://github.com/celfons/kya-brasil/blob/main/anchors/icp-brasil.pem) in the repository,
not in the npm package: fetch it from a pinned commit
(`https://raw.githubusercontent.com/celfons/kya-brasil/<commit>/anchors/icp-brasil.pem`), review changes to it like
code, and split it with `pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)`. A runnable
example with a throwaway test PKI is in
[examples/quickstart](https://github.com/celfons/kya-brasil/tree/main/examples/quickstart).

A credential from any KYA issuer (the hosted one, yours, a partner's) is checked with that issuer's public key,
published at `<issuer>/.well-known/kya.json`.

```ts
import { verifyCredentialSignature, verifyMandateAuthorization, effectiveStatus, checkAction, hashPaymentRef } from "@kya-brasil/core";

const sig = await verifyCredentialSignature(credential, issuerPublicJwk); // { valid, key_id, signed_at }
if (!sig.valid || effectiveStatus(credential) !== "active") deny();
// D-33: the e-CNPJ / e-CPF signature covers the mandate when the credential carries its hash.
const auth = await verifyMandateAuthorization(credential); // "signed" | "mismatch" | "not_covered" (issued before D-33)
if (auth === "mismatch") deny(); // decide yourself whether "not_covered" (issuer attestation only) is enough
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

## Issuance by the principal (issue it yourself, no issuer service)

There is no native link between an ICP-Brasil certificate and an AI agent: the link is the KYA format, so the
library issues it as well as verifies it. **The issuer is the principal itself**, the holder of the e-CNPJ or e-CPF,
not a service in between: no account, no API, no one else sees the certificate or decides on the powers. In a
delegation, the parent agent is the issuer of its sub-agent's mandate. SPEC section 20, decision D-37.

Issuance is symmetric to verification and uses the same functions: the mandate is validated by the verifier's
schema, hashed with the same canonical JSON (RFC 8785; SPEC section 7), and the text the certificate signs is the same
challenge text `verifyPrincipalProof` reads. Every risk field is required (no defaults: `[]` says "any",
`delegation: null` says "may not delegate"), and whatever verification would refuse is refused at issuance.

```ts
import { buildMandate, mandateSigningInput, assembleCredential, verifySelfIssuedCredential, openPfx, encodePrincipalProofHeader } from "@kya-brasil/core";

// 1. The principal states the powers. Missing field = error.
const built = await buildMandate({
  credential_id: crypto.randomUUID(),
  agent: { kind: "evm", id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" },   // the agent's public key
  principal: { kind: "company", cnpj: "11.222.333/0001-81" },                // or { kind: "person" } (e-CPF)
  mandate: {
    actions: ["quote", "order", "pay"],
    max_per_operation: { amount: 5000, currency: "BRL" },
    max_per_day: { amount: 20000, currency: "BRL" },
    currencies: ["BRL"],
    counterparties: ["33000167000101", "*.fornecedor.com.br"],
    payment_instruments: [],
    valid_from: "2026-11-01T00:00:00Z",
    valid_until: "2027-03-01T00:00:00Z",
    delegation: { max_depth: 1, max_ttl_seconds: 3600 }                      // or null
  },
  ttl_seconds: 30 * 86400,
  now: new Date()
});

// 2. The exact bytes the certificate signs (text, UTF-8 bytes and their SHA-256).
const { text } = await mandateSigningInput(built);

// 3. Sign with any ICP-Brasil signer that produces a CMS (detached or attached, SHA-256, RSA PKCS#1 v1.5):
//    an A1 file here; a token, HSM or cloud certificate through ecnpjSigner / buildDetachedCms / cloudSigner.
const signer = await openPfx(pfxBytes, password);
const cms = await signer.sign(text);

// 4. Assemble: checks the signature, the chain to the anchors and the CNPJ as a verifier will, and refuses otherwise.
const { credential, proof } = await assembleCredential(built, cms, [], { anchors: icpBrasilAnchors, now: new Date() });
// Check the certificate's CRL now (checkRevocation), then hand { credential, proof } to the agent.

// 5. The agent presents both; any verifier checks them against ICP-Brasil alone.
const header = encodePrincipalProofHeader(proof);                            // KYA-Principal-Proof
const r = await verifySelfIssuedCredential({ credential, proof, anchors: icpBrasilAnchors, now: new Date() });
// r.ok; r.checks: signature, certificate, agent, principal, issuer, mandate, credential, validity
```

A self-issued credential has `issuer: "urn:kya-brasil:self"` and no issuer attestation: the principal's signature is
the proof, and its status is the certificate's (CRL) and the credential's own expiry, which never passes the
mandate's `valid_until` nor the certificate's end of validity. To revoke before that, the principal revokes the
certificate or issues mandates with short lifetimes; there is no status service to ask. The certificate signer
stays outside the core: an A3 token (PKCS#11 and PIN) is `openToken` in `@kya-brasil/agent-tools`.

**Co-signature by a legal representative (SPEC section 21).** Holding the company's e-CNPJ does not make someone its
representative. A self-issued company credential may carry co-signatures by e-CPF over the same text; the verifier
supplies the representatives (the QSA, from its own source) and the core counts them:

```ts
import { addCosignature, verifyCompanyWill } from "@kya-brasil/core";

const repCms = await representativeSigner.sign(proof.text);                 // e-CPF, the SAME text
const cosigned = await addCosignature({ credential, proof }, repCms, [], { anchors: icpBrasilAnchors, now: new Date() });
const will = await verifyCompanyWill(cosigned, { anchors: icpBrasilAnchors, now: new Date(), representatives: (cnpj) => qsaCpfs(cnpj), minCosigners: 1 });
// will.ok, or will.code: NO_COSIGNATURE | COSIGNER_NOT_REPRESENTATIVE | COSIGNATURE_TEXT_MISMATCH |
// COSIGNER_CERTIFICATE_INVALID | COSIGNATURE_NOT_RECORDED | INSUFFICIENT_COSIGNERS | COMPANY_SIGNATURE_INVALID
```

The credential records only the e-CPF certificate's hash, issuer and dates; the CMS (which carries the certificate,
and so the CPF) travels in the proof (`proof.cosignatures`, also in `KYA-Principal-Proof`). The result has no CPF.

With no list of representatives, the verifier can accept the person responsible named in the e-CNPJ itself (its
otherName 2.16.76.1.3.4, checked by the registration authority at issuance). Both sources may be used together:

```ts
const will = await verifyCompanyWill(cosigned, { anchors: icpBrasilAnchors, now: new Date(), acceptCertificateResponsible: true });
// will.cosigners[i].basis: "ecnpj_responsible" (or "representatives" when it came from the list)
```

This rests on the e-CNPJ being revoked when that person stops representing the company, and it names one person:
attorneys-in-fact and joint signature still need the list.

Delegation, issued by the parent agent with its own key:

```ts
import { buildDelegation, assembleDelegation, encodeDelegationHeader } from "@kya-brasil/core";

const prepared = await buildDelegation({ credential }, {
  delegate: { kind: "evm", id: subAgentAddress },
  mandate: { ...narrowerTerms, delegation: null },  // all fields required; refused if broader than the parent's
  ttl_seconds: 600,
  now: new Date()
});
const chain = await assembleDelegation({ credential }, prepared, await agentAccount.signMessage({ message: prepared.text }), new Date());
// KYA-Delegation: encodeDelegationHeader(chain); verifiers use verifyDelegationChain, unchanged.
```

## Without trusting the issuer

Since D-33 the e-CNPJ / e-CPF signs the agent and the mandate's hash, and the principal keeps the signed text and the
`.p7s`. When the principal hands them to its agent, you can check the authorization against ICP-Brasil alone (SPEC
section 19), and the issuer's key vouches only for the credential's status:

```ts
import { decodePrincipalProofHeader, verifyPrincipalProof, checkRevocation } from "@kya-brasil/core";

const proof = decodePrincipalProofHeader(request.headers.get("KYA-Principal-Proof")!);
const r = await verifyPrincipalProof({ credential, proof, anchors: icpBrasilAnchors, now: trustedClock() });
// r.ok; r.checks: signature, certificate, agent, principal, issuer, mandate (each with its reason)
// then the certificate's revocation, with a CRL you fetched from r.revocation.crl_urls:
// await checkRevocation({ crlDer, serial: r.revocation!.serial_number, issuerCertificate: r.revocation!.issuer_certificate!, pastNextUpdate: "refuse" })
```

The CMS carries the signer's certificate (personal data): the principal decides when to share it, and you use it for
this check only. The result carries nothing personal.

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

## Status freshness proportional to the amount (offline)

Offline, a verifier only has status evidence of some age: an answer the issuer signed (the credential's status) or a
CRL (the certificate's). How old is acceptable is the verifier's call, because the verifier runs the risk (SPEC
section 18). Declare the expected loss you accept per action (`L`) and the revocation rate you assume (`λ`, per hour);
the maximum age is `L / (amount × λ)`, capped by your ceiling. The library holds no business values: every
parameter below is required, and so is the clock.

```ts
import { freshnessPolicy, checkFreshAction, evidenceFromSignedStatus, evidenceFromRevocation } from "@kya-brasil/core";

const policy = freshnessPolicy({
  max_expected_loss: { amount: 1, currency: "BRL" },               // L: your tolerance, per action
  revocation_rate_per_hour: { credential: lambda, certificate: mu }, // λ: what you assume
  require: ["credential"],                                          // add "certificate" to also require a CRL
  max_age_seconds: ceiling,                                         // your ceiling, whatever the value
  max_clock_skew_seconds: skew,                                     // tolerance for evidence dated in the future
  unvalued_action: "refuse",                                        // or "ceiling": actions of unknown value
  past_valid_until: "refuse",                                       // or "accept": a CRL past nextUpdate, judged by age
  // action_risk_value: { sign_contract: 100_000 }, max_age: ({ amount, kind, action }) => seconds
});

// The agent may staple a recent signed verdict to its request: then no network is needed.
const evidence = [await evidenceFromSignedStatus(stapledVerdict, issuerPublicJwk, credential.credential_id)];
// evidence.push(evidenceFromRevocation(await checkRevocation({ crlDer, serial, issuerCertificate, pastNextUpdate: "accept" })));

const r = checkFreshAction(credential.mandate, { action: "buy", amount: 4200, currency: "BRL", now: trustedClock() }, { policy, evidence });
// r.allowed; r.freshness.refresh = kinds to fetch again (or ask the agent for); r.freshness.applied = policy and
// clock used, keep it with the verdict as the risk you accepted
```

Actions without an amount (signing, reading data, calling an API) take the risk value you assign them:
`action_risk_value: { sign_contract: 100_000, read_data: 50 }` in the policy's currency; an action with neither an
amount nor a risk value is refused or gets the ceiling, as `unvalued_action` says. A custom `max_age` also receives the action.
The daily ceiling (`max_per_day` with your own `spent_today`) is what bounds a stolen key inside the window; the
counting, and any stricter ceiling of your own, are yours.

It fails closed: no evidence, another currency, an invalid amount, a missing or invalid clock, evidence dated in the
future beyond your skew, or a CRL past its `nextUpdate` when `past_valid_until` is `"refuse"`. The freshest statement wins, so a later revocation beats an earlier "active".
`checkFreshness` and `maxStatusAgeSeconds` are available on their own.

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
  validateMandate, mandateSha256, buildCredential, signCredential, importPrivateKey, generateAttestationKey
} from "@kya-brasil/core";

const key = await generateAttestationKey();               // once; keep privateKeyPkcs8 secret, publish publicJwk
const m = validateMandate(mandate);
const mandate_sha256 = await mandateSha256(m);            // the e-CNPJ signs this hash with the challenge (D-33)
const ch = newChallenge({ issuer: "https://kya.acquirer.example", agent, cnpj, mandate_sha256 });
// The agent signs ch.text with its key; the company signs ch.text with its e-CNPJ (detached CMS).
if (!(await verifyAgentSignature(agent, ch.text, agentSignature))) throw new Error("agent signature");
const icp = await verifyIcpSignature({ cmsBase64: ecnpjSignature, challenge: ch.text, expectedCnpj: cnpj, anchors });
// anchors: the ICP-Brasil roots as PEM strings (bundle in the repository: anchors/icp-brasil.pem).
const crlDer = await fetchCrl(icp.crl_urls);             // yours: HTTP + cache
const rev = await checkRevocation({ crlDer, serial: icp.serial_number, issuerCertificate: icp.issuer_certificate!, pastNextUpdate: "refuse" });
if (rev.revoked) throw new Error("certificate revoked");

const credential = await signCredential(
  buildCredential({
    credential_id: crypto.randomUUID(), agent, cnpj,
    legal_name, registration_status,                      // from your registration source; "UNVERIFIED" if none answered
    certificate: { sha256: icp.certificate_sha256, subject: icp.certificate_subject, issuer: icp.issuer, signed_at: icp.signed_at, not_after: icp.not_after },
    mandate: m, mandate_sha256,
    ttl_seconds: 30 * 86400,                              // your risk decision; capped by the certificate and the mandate (D-35)
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
