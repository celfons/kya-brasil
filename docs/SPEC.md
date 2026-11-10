# KYA Credential v1

A **KYA credential** states that a company, identified by its e-CNPJ (ICP-Brasil) certificate, declared
that an AI agent key acts on its behalf within a mandate, and that on the dates shown the certificate
was not revoked and the company was active at the Receita Federal. It attests the link between agent and
company, not the company's risk: sanctions, debt or litigation are for the verifier to weigh with its own
sources. It is a JSON document signed with Ed25519 by the issuer. Anyone can
verify it offline with the issuer's published key; the live status is read from the issuer.

This document is the normative description of the format and of the verification procedure. The
reference implementation is `packages/core` in this repository; `docs/vectors/credential-v1.json` holds
test vectors, verified by `packages/core/src/vectors.test.ts`.

Keywords MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Actors

| Actor | Holds | Does |
| --- | --- | --- |
| Company (principal) | e-CNPJ certificate (ICP-Brasil A1 or A3) | Declares the mandate, signs the challenge, revokes. |
| Agent | An EVM key (secp256k1) or a Web Bot Auth key (Ed25519) | Signs the challenge; later signs its requests. |
| Issuer | An Ed25519 signing key, published | Verifies both signatures, the certificate's revocation and the company's registration, issues, reviews daily, publishes status. |
| Verifier | Nothing | Checks a credential before accepting an agent's action. |

## 2. Agent keys

```
AgentKey = { kind: "evm" | "web-bot-auth" | "erc8004", id: string, wallet?: "0x..." }
```

- `evm`: `id` is the EIP-55 checksummed address. Signatures are EIP-191 `personal_sign` over the UTF-8 challenge text, hex encoded.
- `web-bot-auth`: `id` is the raw 32-byte Ed25519 public key, base64url without padding. Signatures are raw Ed25519 over the UTF-8 challenge text, base64url without padding.
- `erc8004`: `id` is `eip155:<chainId>:<identityRegistry>:<agentId>`, an agent registered as an ERC-721 token in an
  [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) Identity Registry (registry address checksummed, agentId decimal).
  The key that signs is the agent's on-chain `agentWallet` (`getAgentWallet(agentId)`, falling back to `ownerOf`),
  with EIP-191 as for `evm`. The issuer MUST resolve the wallet on chain at registration and again at proof time,
  record it in `credential.agent.wallet`, and MUST suspend the credential when a later review finds a different
  wallet. Verifiers SHOULD compare the request signer with `agent.wallet` and MAY re-read the chain.

Issuers MUST normalize `id` (checksum the address; canonical base64url) before storing or comparing.

## 3. Challenge

The issuer hands the company a one-time challenge that binds issuer, agent, CNPJ, mandate and expiry, so a
signature cannot be replayed for another company, another issuer or other powers. The text MUST be exactly these
seven lines joined by `\n`, no trailing newline:

```
KYA Brasil: prove this agent key acts for a company
issuer: <issuer origin>
challenge: <challenge_id, uuid>
agent: <kind>:<id>
cnpj: <CNPJ: 14 characters, 12 digits or upper-case letters then 2 check digits>
mandate-sha256: <lowercase hex SHA-256 of the canonical JSON (section 7) of the mandate>
expires: <ISO 8601 UTC>
```

The challenge MUST expire within 15 minutes and MUST be consumed on first use, successful or not.

The issuer MUST keep, with each challenge, the mandate requested when it was created, and MUST issue that mandate
when the challenge is proved, never a mandate changed later. A new registration for the same agent and principal
MUST void the challenges still outstanding, so a signing link already handed to the certificate holder cannot issue a
mandate other than the one it showed.

Since D-33 the certificate signature covers the mandate: the `mandate-sha256:` line is the hash of the mandate kept
with the challenge, and the issuer MUST refuse to issue when the signed text does not carry the hash of the mandate it
is about to issue (a challenge created before D-33 carries none and is refused; challenges expire within 15 minutes).
The credential records that hash in `authorized_by.mandate_sha256` (section 6), so any verifier can check offline that
the mandate it reads is the one the principal signed. The signing page computes the same hash in the browser and warns
when it does not match the mandate it shows. The signed text and the detached CMS stay with the principal, who can
download them from the signing page: the issuer does not keep the CMS, which carries the signer's certificate and so
personal data (section 12). With them, anyone can verify with an ICP-Brasil validator that the principal authorized
this agent with these powers.

## 4. Company proof (e-CNPJ)

The company signs the challenge text with its e-CNPJ certificate as a **CMS/PKCS#7 SignedData** (RFC 5652),
DER, base64, preferably detached. Signed attributes (content type, message digest, signing time) MAY be
present. The issuer MUST:

1. Parse the CMS, require exactly one `SignerInfo`, and verify the signature over the challenge bytes. When the
   CMS is attached (carries `eContent`, as many desktop signers produce), the embedded content MUST equal the
   challenge text byte for byte (UTF-8, no added line break); otherwise any document the company ever signed
   would pass as consent.
2. Take the signer certificate from the CMS and read the CNPJ from the Subject Alternative Name
   `otherName` with OID `2.16.76.1.3.3` (ICP-Brasil DOC-ICP-04), or from the subject CN suffix
   `:<cnpj>` as a fallback. The CNPJ MUST equal the one in the challenge.
3. Validate the chain from the signer certificate to a trusted ICP-Brasil root (the issuer's anchor set),
   including validity dates at verification time.
4. Check that the signer certificate is not revoked: fetch the CRL (LCR) from a distribution point named
   in the certificate, verify its signature with the issuing AC's certificate, reject it when past its
   `nextUpdate`, and look the serial number up. A listed certificate MUST NOT authorize anything (issuance,
   renewal, company requests of section 13). When no trustworthy CRL can be obtained the issuer MUST refuse
   (fail closed). OCSP MAY be used in addition.
5. Record only the certificate SHA-256, subject, issuer, serial number, the issuing AC's certificate, the
   CRL URLs and the signing time. The signer's CPF and any other personal field in the certificate MUST
   NOT be stored or published.

**Signing in practice (D-26).** The issuer serves `GET /sign`, a page for the e-CNPJ holder (owner or
accountant) opened from the `sign_url` returned by registration, with `&agent_signature=` appended by the
agent. It shows the CNPJ, the agent, the issuer, the expiry and the requested mandate, warns when the challenge
names another issuer or has expired, and signs in the browser: an A1 `.pfx`/`.p12` (the file and password never
leave the browser), or a `.p7s` produced by any ICP-Brasil signer over the downloaded challenge file (A3 token or
card, cloud certificates). With both signatures it calls `/prove`. `GET /v1/agents/{id}/sign-link?challenge_id=&agent_signature=` (free; MCP
`kya_sign_link`) returns the same link with the agent's signature, from the stored challenge, without consuming it.
The same signing is available as code in `@kya-brasil/core` (`openPfx` for A1 files, `ecnpjSigner` for any signer
that produces RSA PKCS#1 v1.5 SHA-256 signatures: PKCS#11 tokens, HSMs, cloud certificates) and as a command
(`kya-sign --pfx` or `kya-sign --pkcs11`) in `@kya-brasil/agent-tools`; none of them needs the page.

**Cloud certificates (D-28).** A provider implements `CloudSignatureProvider` (OAuth 2.0 authorization code with PKCE
S256; a session that returns the certificate and signs a SHA-256 hash with RSA PKCS#1 v1.5). The issuer's flow:
`GET /sign/cloud/{provider}/start?id=&challenge_id=&agent_signature=` stores the PKCE verifier and the request
under a random `state` for at most 10 minutes and redirects to the provider; `GET /sign/cloud/callback?code=&state=`
consumes the state (single use), exchanges the code, signs only the stored challenge, discards the session and
calls `/prove`. `/status` lists `cloud_providers`. The reference issuer configures none.

Note on the otherName: ICP-Brasil encodes the CNPJ as a 14-character ASCII string in an OCTET STRING or a
PrintableString, depending on the AC; implementations SHOULD accept both and keep the 14 characters, dropping
punctuation. Since July 2026 a CNPJ may be alphanumeric (IN RFB 2.229/2024): the first 12 positions are digits or
letters, the last 2 are digits, and letters are compared upper-cased. An implementation that keeps only digits
cannot read the CNPJ of such a company.

## 5. Mandate

A JSON object validated by the public schema (`/.well-known/kya-mandate.schema.json`). Reserved fields
are evaluated by the issuer; every other field is kept verbatim and listed under `not_evaluated` in
verdicts.

| Field | Type | Evaluated as |
| --- | --- | --- |
| `actions` | string[] (lowercase, `^[a-z][a-z0-9_-]{1,31}$`) | action MUST be in the list |
| `max_per_operation` | `{ amount: number > 0, currency: string }` | amount MUST be ≤ ceiling, same currency |
| `max_per_day` | `{ amount, currency }` | amount + `spent_today` (caller supplied) MUST be ≤ ceiling |
| `currencies` | string[] (`^[A-Z0-9]{2,10}$`) | currency MUST be in the list |
| `counterparties` | string[] (CNPJ digits, domain, `0x` address; `*.` prefix matches subdomains) | counterparty MUST match an entry; empty or absent = any |
| `payment_instruments` | `{ network, ref_sha256, label? }[]` (up to 20) | the instrument given (`payment_ref_sha256`, optionally `payment_network`) MUST match an entry; empty or absent = any |
| `valid_from`, `valid_until` | ISO 8601 | now MUST be inside the window |
| `delegation` | `{ max_depth: 1..3, max_ttl_seconds: 60..86400 }` | not a rule on actions: allows sub-agents (section 17); absent = no delegation |

A check is only performed when both the mandate field and the query field are present.

**Payment instruments (D-25).** For card networks, acquirers and issuers: each entry names a network or rail
(`^[a-z][a-z0-9_-]{1,31}$`: `visa`, `mastercard`, `elo`, `amex`, `hipercard`, `pix`, `x402`, ...) and
`ref_sha256`, the lowercase hex SHA-256 of a reference the network already gives for the instrument (network
token reference, Payment Account Reference), computed over its UTF-8 bytes with whitespace removed and case
kept. It MUST NOT be, contain or be derived from a card number in a reversible way; issuers MUST refuse a value
that is not 64 hex characters and labels carrying runs of 12 or more digits. The verifier hashes the reference
it received in the transaction and passes it to `/allowed` (or to `checkAction` in `@kya-brasil/core`); the
signed verdict then states whether that instrument belongs to an agent the company authorized. The serialized
mandate MUST NOT exceed 8192 bytes.

## 6. Credential

```json
{
  "credential_id": "uuid",
  "version": 1,
  "agent": { "kind": "evm", "id": "0x..." },
  "principal": { "cnpj": "11222333000181", "cnpj_formatted": "11.222.333/0001-81", "legal_name": "ACME LTDA", "registration_status": "ATIVA" },
  "authorized_by": { "method": "icp-brasil-e-cnpj", "certificate_sha256": "hex", "certificate_subject": "CN=...", "issuer": "CN=AC ...", "signed_at": "ISO 8601", "mandate_sha256": "64 hex" },
  "mandate": { ... },
  "kyb_snapshot": null,
  "status": "active",
  "status_reason": null,
  "issued_at": "ISO 8601",
  "expires_at": "ISO 8601",
  "issuer": "https://issuer.origin",
  "verify_url": "https://issuer.origin/v1/agents/<credential_id>",
  "revocation_url": "https://issuer.origin/v1/agents/<credential_id>/status",
  "attestation": { "algorithm": "ed25519", "key_id": "16 hex", "sha256": "64 hex", "signed_at": "ISO 8601", "signature": "base64", "verify_url": "..." }
}
```

- `expires_at` MUST NOT be later than `mandate.valid_until` nor than the `notAfter` of the certificate that signed the
  challenge (D-35), so a proof checked against ICP-Brasil (section 19) never fails while the credential reads as
  active. The lifetime itself is the issuer's risk decision: the core has no default (`ttl_seconds` is required) and
  the reference issuer uses 90 days.
- `authorized_by.mandate_sha256` (D-33) is the hash the signed challenge carried, and MUST equal the SHA-256 of the
  canonical JSON of `mandate`. Credentials issued before D-33 do not have it: their mandate rests on the issuer's
  attestation only.
- Issuance MUST be refused when the certificate is revoked (section 4) or when the company's registration at the Receita Federal is confirmed as other than `ATIVA`. Nothing else about the company (sanctions, debt, risk score) affects issuance or status.
- The registration check is optional and never blocks on its own failure (D-24). When the issuer has it off, `principal.registration_status` is `NOT_CHECKED`; when no source answers, `UNVERIFIED`. In both cases the credential is issued, `legal_name` comes from the e-CNPJ certificate, and the issuance response carries the reason in `warnings` (and in `kyb_warnings`, kept for v1). The daily review checks again and suspends if a later answer is not `ATIVA`. Verifiers that require a confirmed status MUST check for `ATIVA`.
- `kyb_snapshot` is kept in v1 for compatibility and is `null` in credentials issued by the reference issuer since D-23. Older credentials may carry a risk screen taken at issuance (an object with `risk_level`, `active_sanctions`, `checked_at` and similar); it never affected status and verifiers MUST NOT read it as a current assessment.
- `status` is the status **at issuance**. Later changes (suspension by the daily review, revocation, expiry) are not re-signed; they are published at `verify_url` and in the revocation list.

## 7. Signature (attestation)

1. Remove the `attestation` and `receipt` fields.
2. Canonicalize as RFC 8785 (JSON Canonicalization Scheme, JCS): no whitespace; object members sorted at every level by the UTF-16 code units of their names; arrays in order; strings and numbers serialized as ECMAScript does (RFC 8785 sections 3.2.2.2 and 3.2.2.3). An implementation in any language that follows RFC 8785 produces the same bytes. A number that is not finite, a string with a lone surrogate, or a value of a type JSON does not have MUST be refused (`INVALID_INPUT`), never serialized; a verifier that meets one treats the document as not matching its hash. `canonicalize` in the core is the one implementation, and its tests run the samples of the RFC (sections 3.2.2 to 3.2.4 and Appendix B).
3. `sha256` = hex SHA-256 of the UTF-8 canonical string.
4. The signed message is the UTF-8 string `<sha256>\n<signed_at>`.
5. `signature` = base64 of the Ed25519 signature over that message.
6. `key_id` = first 16 hex characters of SHA-256 of the canonical JWK `{"crv":"Ed25519","kty":"OKP","x":"..."}`.

The issuer publishes its keys at `/.well-known/kya.json`: `{ keys: [{ key_id, jwk, status: "active" | "retired", retired_at? }] }`. A rotated key MUST stay published as `retired` so earlier credentials still verify.

The same procedure signs verdicts (section 9) and paid verification receipts.

## 8. Verification procedure

A verifier that receives a credential (or a `credential_id`) with an agent's request MUST:

1. **Binding**: confirm that the key that signed the agent's request equals `credential.agent.id` (same `kind`). A credential alone proves nothing about who is talking.
2. **Signature**: fetch the issuer's keys, pick the one whose `key_id` equals `attestation.key_id`, and run section 7 in reverse. Reject on hash mismatch or bad signature.
   **Mandate authorization** (D-33): when `authorized_by.mandate_sha256` is present, it MUST equal the SHA-256 of the canonical JSON of `mandate` (`verifyMandateAuthorization` in the core); reject otherwise. When it is absent, the mandate rests on the issuer's attestation alone, and the verifier decides whether that is enough.
   **Without trusting the issuer** (D-34): when the agent presents the principal's own proof (section 19), the verifier MAY check the binding and the mandate against ICP-Brasil itself, so that the issuer's key vouches only for the credential's status.
3. **Live status**: `GET verify_url`. Accept only `status == "active"`. Verifiers that cache credentials SHOULD poll `/v1/revocations?since=` at least daily. When the issuer is unreachable, steps 2 and 4 still work offline but say nothing about a later suspension or revocation; accepting such a credential is the verifier's risk until `expires_at`. Section 18 lets the verifier bound that risk: it states how old the status evidence may be for the amount at stake.
4. **Expiry**: `now < expires_at`.
5. **Mandate**: either evaluate section 5 locally, or request a signed verdict from the issuer (section 9) and keep it as evidence.

## 9. Verdict

`GET /v1/agents/{id}/allowed?action=&amount=&currency=&counterparty=&spent_today=&payment_network=&payment_ref_sha256=` returns:

```json
{ "credential_id": "...", "status": "active", "allowed": true, "reason": "inside the mandate",
  "query": { ... }, "checks": [{ "rule": "actions", "ok": true, "detail": "..." }, ...],
  "not_evaluated": ["notes"], "checked_at": "ISO 8601", "attestation": { ... } }
```

Every query parameter is echoed in `query`, so the signed verdict records the instrument that was checked; it is
evidence for a later dispute ("the company's mandate covered this agent, this instrument and this amount at
`checked_at`").

`allowed` is true only when the live status is `active` and every performed check passed. The verdict is signed as in section 7, so the verifier can keep it as proof of what the issuer said at `checked_at`.

## 10. Revocation

The company signs, with its e-CNPJ (section 4), the text `KYA Brasil: revoke <credential_id>\n<nonce>`.
The issuer MUST set the status to `revoked` at once, record the event, and list it in
`GET /v1/revocations?since=`. Revocation is final; a new registration issues a new credential.

## 11. Daily review

At least daily, on every `active` or `suspended` credential, the issuer MUST check the two things it
attests, recording each change as an event:

1. **Certificate.** The CRL of the e-CNPJ that authorized the credential (section 4). What a listed
   certificate does is the relying party's policy (D-36, `revocationEffect` with a
   `CertificateRevocationPolicy`): for each RFC 5280 reason, revoke, suspend or keep, and for any other reason,
   an entry without one included, revoke or suspend (never keep). Whatever the policy, an authorization is never
   kept when the certificate was revoked before it, or when the AC's `invalidityDate` (suspected compromise) is
   not after it. The reference issuer revokes (final), except: `certificateHold` suspends until the entry
   disappears, and `superseded` or `cessationOfOperation` dated after the authorization change nothing (the
   certificate was replaced or retired without compromise; the signature stands). An unreachable CRL changes
   nothing that day. A verifier checking the principal's proof itself (section 19) applies its own policy the
   same way.
2. **Registration.** The company's status at the Receita Federal: not `ATIVA` suspends the credential;
   `ATIVA` again reinstates it.

ERC-8004 credentials are also suspended when the on-chain wallet changes (section 2); that suspension is
not lifted by the review.

## 12. Privacy

For companies only legal-entity data is processed. The credential and the issuer's records MUST NOT contain
the CPF or the name of the natural person who holds the e-CNPJ; the certificate hash identifies the
authorization. For person credentials (section 16) the issuer keeps only a keyed hash of the CPF, never the
name, the CPF in clear or the certificate subject.

## 13. Company: inventory and events

The issuer does not record what agents do (acts were removed in 0.5.0, D-19). `max_per_day` is evaluated with
the `spent_today` the verifier supplies. What the issuer offers the company instead:

**Requests.** Text signed with the e-CNPJ (section 4, including the revocation check), lines joined by `\n`:

```
KYA Brasil: <verb> <cnpj: 14 characters, as in section 4>
[extra lines]
at: <ISO 8601 time>
```

The issuer MUST reject `at` more than 10 minutes away from its clock.

- **Inventory**, `POST /v1/companies/{cnpj}/agents` with `{ signed_text, ecnpj_signature }`, verb `agents`:
  every credential registered for the CNPJ in any status, whoever held the certificate.
- **Webhook**, `POST /v1/companies/{cnpj}/webhook`, verb `webhook`, one extra line `url: <https URL | ->`
  (`-` removes it). The URL MUST be https on a host name (no IP literal, no credentials). The request MUST
  be newer (`at`) than the last accepted one, so a captured request cannot be replayed.

**Events.** On `credential.issued`, `credential.renewed`, `credential.suspended`, `credential.reinstated` and
`credential.revoked` the issuer POSTs `{ event, cnpj, at, data, attestation }` to the webhook, signed as in
section 7. Events cover the credential's lifecycle only, never what the agent does or is asked (D-19).
Delivery is best effort (one attempt, 5 s timeout); the company checks the attestation before trusting an
event and uses the inventory as the source of truth.

## 14. Request signing ("Sign in with KYA")

An agent presents its credential on every request by signing the request with its key. Headers:

| Header | Value |
| --- | --- |
| `KYA-Credential` | `credential_id` |
| `KYA-Created` | Unix seconds when the signature was made |
| `KYA-Expires` | Unix seconds after which it is invalid (at most 600 s after `KYA-Created`) |
| `KYA-Signature` | EIP-191 hex (`evm`, `erc8004`) or raw Ed25519 base64url (`web-bot-auth`) over the request text |
| `KYA-Content-SHA256` | hex SHA-256 of the body, present whenever the request has a body |
| `KYA-Delegation` | only on a request signed by a sub-agent: base64url (no padding) of the JSON delegation chain (section 17) |
| `KYA-Credential-Document` | optional, for verifiers that work without the issuer: base64url (no padding) of the credential's JSON (section 6) |
| `KYA-Principal-Proof` | optional, with `KYA-Credential-Document`: the principal's proof (section 19) |

Request text, lines joined by `\n`:

```
KYA Brasil: request
credential: <credential_id>
[delegation: <hex SHA-256 of the KYA-Delegation header value>]   (only when that header is sent)
method: <METHOD, upper case>
url: <scheme>://<host, lower case>[:port if not default]<path>[?query]
created: <KYA-Created>
expires: <KYA-Expires>
content-sha256: <KYA-Content-SHA256 | ->
```

The verifier MUST reject a signature whose `created` is more than 300 s in the future or whose `expires` has
passed, MUST recompute the body hash when a body is present, MUST verify the signature with the credential's
agent key (`agent.id`, or `agent.wallet` for `erc8004`), or, when `KYA-Delegation` is present, with the key of
the last delegate after verifying the chain (section 17), and MUST accept only `status == "active"`. It MAY
cache the credential for a short time (60 s in the reference client) and SHOULD honour `/v1/revocations`.
A verifier SHOULD refuse
replays: it records each accepted request under the SHA-256 of its request text and keeps the record at least
until that request's `expires` (a record kept for less lets the same request through again inside its window), and
it refuses a request already recorded (`401 KYA_REQUEST_REPLAYED`). It records only after the request verified,
needs a bounded lifetime (`expires - created` at most 600 s), and, when several instances serve one API, a shared
store that records atomically. Reference: the `replayCache` option of `createKyaAuth` (`memoryReplayCache()` for a
single process), in both the issuer and the offline modes. This profile is deliberately simple; an RFC 9421 (HTTP Message Signatures) binding for `web-bot-auth` keys
is planned and will carry the same `KYA-Credential` header.

**Without the issuer.** A verifier MAY accept the credential from the request instead of fetching it: the agent
sends `KYA-Credential-Document` and `KYA-Principal-Proof` (neither is in the request text: the principal's
signature binds them). The verifier then MUST check that the document's `credential_id` equals `KYA-Credential`,
verify the request signature as above, verify the proof against ICP-Brasil trust anchors and a clock of its own
(section 20 for `issuer` = `urn:kya-brasil:self`; otherwise section 19 plus the issuer's attestation, section 7,
with a key it already holds, so that the credential's own fields are not the agent's word), check the
certificate's revocation with evidence it trusts (section 18), and evaluate every mandate, the delegation chain's
included, locally. Status changes made only at an issuer go unseen (section 19). Reference: the `offline` option of
`createKyaAuth` in `@kya-brasil/agent-tools`.

### 14.1 Mutual authentication (agent to agent)

When the callee is also an agent, it proves itself by signing the response, bound to the request it answers.
Response headers: the same `KYA-*` names plus `KYA-In-Reply-To` = hex SHA-256 of the request's
`KYA-Signature`. Response text:

```
KYA Brasil: response
credential: <callee credential_id>
in-reply-to: <KYA-In-Reply-To>
created: <KYA-Created>
expires: <KYA-Expires>
content-sha256: <hex of the response body | ->
```

The caller MUST check `in-reply-to` against the signature it sent, the validity window, the body hash, and
verify the signature with the callee credential's agent key, accepting only `status == "active"`. A verifier
MUST NOT accept a response text as a request (the first line differs), so a signed response cannot be replayed
as a request from the callee.

## 15. Test vectors

`docs/vectors/credential-v1.json` contains an issuer key, a challenge with its text, a signed credential,
a signed verdict and a tampered copy of the credential that MUST fail verification. An implementation is
conformant with this document when it accepts the credential and the verdict, rejects the tampered copy,
reproduces the challenge text from its fields, and reaches the same `allowed` result for the mandate.

`docs/vectors/self-issued-v1.json` (section 20) contains a throwaway test anchor, an issuance input, the built
mandate, the signing input, a self-issued credential with its proof, and a tampered copy that MUST fail.
`docs/vectors/mandate-conformance.json` contains 1,320 vectors generated by the Alloy model in `docs/formal/`
(containment, actions, and since D-37 issuance of delegations).

## 16. Natural persons (D-29)

An agent MAY act for a natural person who signs with an ICP-Brasil **e-CPF**.

- Registration: `POST /v1/agents` with `principal: "person"` and no `cnpj`. The challenge text starts with
  `KYA Brasil: prove this agent key acts for me, a natural person`, carries `principal: person (e-CPF)`, a
  `mandate-sha256:` line as in section 3 (D-33), and a `consent:` line in which the person authorizes the issuer to keep a keyed hash of the CPF while the credential is
  valid and to answer paying verifiers whether a CPF they already have matches. Signing the text records consent.
- Proof: the CMS is verified as in section 4, except that the signer certificate MUST be an e-CPF (CPF read from
  the `2.16.76.1.3.1` otherName, characters 9 to 19, or the common name suffix `:<11 digits>`) and MUST NOT be an
  e-CNPJ. The issuer computes `HMAC-SHA256(key, "kya:cpf:" || CPF)` with a secret, versioned key, stores that value
  and the key version, and discards the CPF. It MUST NOT store the CPF, the name or the certificate subject.
  A renewal MUST be signed by the same CPF.
- Credential: `principal = { "kind": "person", "verified_by": "icp-brasil-e-cpf" }`,
  `authorized_by.method = "icp-brasil-e-cpf"` without `certificate_subject`. Nothing personal is published.
  Verifiers that only handle companies MUST check `principal.kind` before reading `principal.cnpj`.
- Matching: `POST /v1/agents/{id}/principal-match` with `{ "cpf": "…" }` (paid, MCP `kya_principal_match`) answers,
  signed, `{ match, subject_ref? }`. `subject_ref` is `HMAC(key, "kya:subject:" || hash || ":" || verifier)`:
  stable for a verifier, different for each, so verifiers cannot link a person across services. The verifier is the
  x402 payer address. After 3 non-matching answers for a credential, the issuer MUST refuse further checks from
  that verifier for it (429, not charged). The CPF in the request is used for the comparison only.
- The person's inventory: `POST /v1/people/agents` with `"KYA Brasil: my agents\nat: <ISO time>"` signed with the
  e-CPF (within 10 minutes) lists their live credentials and every check made on each (verifier, result, time).
- Revocation: as in section 10, with the revocation text signed by the same e-CPF.
- Retention: the keyed hash and the check log MUST be deleted when the credential is revoked or expires. The daily
  review checks only the e-CPF revocation (there is no public registry status for persons).

## 17. Delegation to sub-agents (D-30)

An agent MAY hand a narrower mandate to another key (a sub-agent) without a new certificate signature, when the
mandate the principal signed allows it: `mandate.delegation = { max_depth, max_ttl_seconds }`. The issuer stores
nothing: the chain travels with each request and any verifier checks it offline against the credential.

A delegation:

```json
{ "version": 1, "credential_id": "6d0b…", "parent": null,
  "delegate": { "kind": "web-bot-auth", "id": "…" }, "depth": 1,
  "issued_at": "2026-10-14T12:00:00.000Z", "expires_at": "2026-10-14T12:10:00.000Z",
  "mandate": { "actions": ["quote"], "max_per_operation": { "amount": 500, "currency": "BRL" } },
  "signature": "…" }
```

Delegation text, signed by the delegator as in section 14 (EIP-191 for `evm`/`erc8004`, raw Ed25519 base64url for
`web-bot-auth`):

```
KYA Brasil: delegation
credential: <credential_id>
parent: <parent | ->
delegate: <kind>:<id>
depth: <depth>
issued: <issued_at>
expires: <expires_at>
mandate-sha256: <hex SHA-256 of the canonical JSON (section 7) of mandate>
```

- `delegate.kind` is `evm` (checksummed address) or `web-bot-auth`; `erc8004` is not accepted as a delegate.
- `mandate` passes the schema of section 5, is at most 2048 bytes serialized, and is in normalized form.
- Depth 1 is signed by the credential's agent key; depth n+1 by the delegate of depth n, with `parent` = hex
  SHA-256 of the signature string of depth n. A chain is an array ordered by depth, at most 3 long.

A verifier MUST, for each delegation i in order, with the credential as delegation 0:
1. require `credential_id` to match, `depth == i`, and `parent` to reference delegation i-1 (null for i = 1);
2. require the mandate of i-1 to carry `delegation`; require `expires_at - issued_at` at most its
   `max_ttl_seconds`, `expires_at` not later than that of i-1 (the credential's `expires_at` for i = 1),
   `issued_at` at most 300 s in the future, and `expires_at` not passed;
3. require the mandate of i to be contained in the mandate of i-1: every reserved field the parent restricts is
   present and at least as restrictive (actions, currencies and payment instruments subsets; ceilings in the same
   currency and not higher; every counterparty covered by a parent entry, `*.` covering the domain and its
   subdomains; validity window inside the parent's); a child `delegation` requires one in the parent, with
   `max_depth` at most the parent's minus 1 and `max_ttl_seconds` not higher;
4. verify the signature over the delegation text with the key of i-1's delegate (the credential's agent key for
   i = 1).

The request is then signed by the last delegate (section 14, with the `delegation:` line). An action is allowed only
when **every** mandate in the chain allows it (credential first); `max_per_day` is evaluated on each level with the
same `spent_today` the verifier supplies. Revoking or suspending the credential ends every delegation under it;
there is no separate revocation of a delegation, which is why its lifetime is short. The issuer's `/allowed` evaluates
the credential's mandate only; delegated mandates are evaluated by the verifier (`checkDelegatedAction` in
`@kya-brasil/core`, `check()` and `allowed()` in the middleware). Error codes: `KYA_DELEGATION_MALFORMED`,
`KYA_DELEGATION_MISMATCH`, `KYA_DELEGATION_NOT_ALLOWED`, `KYA_DELEGATION_TOO_DEEP`, `KYA_DELEGATION_TTL`,
`KYA_DELEGATION_NOT_YET_VALID`, `KYA_DELEGATION_EXPIRED`, `KYA_DELEGATION_BROADER`, `KYA_DELEGATION_BAD_SIGNATURE`.

## 18. Status freshness proportional to the amount (D-32)

Section 8 step 3 asks for the live status; offline, a verifier only has evidence of status that is some time old.
How old is acceptable is the verifier's decision, because the verifier runs the risk (Rivest, *Can We Eliminate
Certificate Revocation Lists?*, Financial Cryptography 1998, proposition 1). This section fixes how that decision is
expressed and checked, so that it is explicit, proportional to what is at stake and kept as evidence.

**Evidence.** `{ kind, in_force, as_of, valid_until?, source?, status? }`, where `kind` is `credential` (the KYA
credential's status) or `certificate` (the ICP-Brasil certificate's status):

- credential: any answer the issuer signed (section 7) that carries `credential_id` and `status`, such as a section 9
  verdict. `as_of` is `attestation.signed_at`; `in_force` is `status == "active"`. The agent MAY staple such an answer
  to its request, so the verifier needs no network;
- certificate: a CRL lookup (section 10 of RFC 5280, `checkRevocation` in the core). `as_of` is the CRL's
  `thisUpdate`, `valid_until` its `nextUpdate`, `in_force` is "serial not listed". Reading a CRL whose nextUpdate has
  passed is itself the caller's choice: `verifyCrl` and `checkRevocation` take `pastNextUpdate: "refuse" | "accept"`,
  with no default (the reference issuer passes `"refuse"`).

**Policy.** The core holds no business values: every parameter that expresses a risk decision is required and comes
from the verifier, and the core only checks that it is well formed. `max_expected_loss` *L* (amount and currency),
`revocation_rate_per_hour` *λ* per kind, `require` (kinds needed), `max_age_seconds` (ceiling),
`max_clock_skew_seconds`, `unvalued_action` (`"refuse"` or `"ceiling"`: what to do with an action of unknown value),
`past_valid_until` (`"refuse"` or `"accept"`: what to do with evidence past its `valid_until`), and optionally
`action_risk_value` and a function `max_age(amount, kind, action)` that replaces the formula. The verifier's clock is
required too. The maximum age for an action of value *v* is

    max_age(v) = min( max_age_seconds, floor( L / (v × λ) × 3600 ) )   seconds

which keeps the expected loss *v × λ × age* at or under *L*. With no amount, a zero amount or *λ* = 0 the ceiling
applies. A custom function's result is clamped to `[0, max_age_seconds]`; a result that is not finite counts as 0.

**Any action.** The policy covers every action, not only payments. For an action with no amount (signing a
document, reading data, calling an API), *v* is the risk value the verifier assigns to that action name in
`action_risk_value` (in *L*'s currency); an amount, when present, takes precedence. An action with neither gets the
ceiling or is refused, as `unvalued_action` says, and the verdict states which. A custom `max_age`
receives the action name too.

**Daily ceilings.** The mandate's `max_per_day` bounds what a stolen agent key can do inside the freshness window
(at most the ceiling per calendar day the window spans), but the count behind it is the verifier's: it supplies
`spent_today` (section 5), and nothing in the core keeps state. Counting, applying a stricter ceiling of its own, or
limiting the number of non-monetary actions per day are the verifier's decisions and risk.

**Check.** For the action's value at risk (its amount, or else its risk value) and every required kind, take the evidence with the latest `as_of` (a newer statement supersedes an older
one, whatever it says). The check passes when that evidence is in force, `valid_until` (if any) is not past unless `past_valid_until` is
`"accept"` (then its age alone decides, as Li and Feigenbaum, FC 2001, propose), `as_of`
is not later than the verifier's clock by more than `max_clock_skew_seconds`, and its age is at most `max_age(v)`.
It fails closed on missing evidence, an amount that is not a finite number ≥ 0, an operation in a currency other than
*L*'s, a missing or invalid clock, or an action of unknown value when `unvalued_action` is `"refuse"`. The verdict lists every check, the kinds for which fresher evidence would change the
answer (`refresh`: fetch it, or ask the agent to staple it), and the policy and clock applied (`applied`), so the
verifier can show later which risk it accepted. An action is allowed only when the mandate (section 5) and the
freshness check both pass (`checkFreshAction` in `@kya-brasil/core`).

No parameter has a default. The rate *λ*, for instance, is a property of the issuer's and of the ACs' revocation behaviour, and the verifier
states the one it assumes. The clock is the verifier's: a wrong clock makes stale evidence look fresh, which is why
the clock used is recorded and evidence dated in the future is refused.

## 19. Proof without trusting the issuer (D-34)

Steps 2 and 3 of section 8 rest on the issuer's key: a compromised or dishonest issuer could sign a credential the
principal never authorized. Since D-33 the principal signs, with the e-CNPJ or e-CPF, a challenge that names the
issuer, the agent, the principal and the mandate's hash, and keeps the signed text and the detached CMS (the
`.p7s` offered by the signing page). When the principal chooses to hand them to its agent, any verifier can check
the authorization against ICP-Brasil alone.

**Presentation.** The agent sends, with the request, the header `KYA-Principal-Proof: <base64url of the JSON
{ "text": <the signed challenge text>, "cms": <the detached CMS, base64 DER> }>`, or the same object in the request
body when headers are too small (`encodePrincipalProofHeader` / `decodePrincipalProofHeader` in the core).

**Check** (`verifyPrincipalProof` in the core), against the credential:

1. the CMS verifies over the text up to the ICP-Brasil trust anchors the verifier holds, and the certificate is an
   e-CNPJ of the credential's CNPJ (company) or an e-CPF (person), valid at the verifier's clock;
2. its SHA-256 equals `authorized_by.certificate_sha256`;
3. the text's `agent:` line equals the credential's agent, its `cnpj:` line the credential's CNPJ (or its `principal:`
   line names a person), and its `issuer:` line the credential's issuer;
4. its `mandate-sha256:` line equals the SHA-256 of the canonical JSON of the credential's `mandate` and, when
   present, `authorized_by.mandate_sha256`.

Every check is reported; the proof passes only when all pass. The verifier then checks the certificate's revocation
with a CRL it trusts (section 18: `checkRevocation`, `evidenceFromRevocation`), using the serial number, issuing AC
certificate and CRL addresses the check returns.

**What is left to the issuer.** Only the credential's status after issuance (a revocation or suspension the principal
asked the issuer for). A verifier that also wants to avoid that dependence relies on the certificate's CRL and on
the expiry of the credential, and accepts that a revocation made only at the issuer goes unseen.

**Privacy.** The CMS carries the signer's certificate: for an e-CPF the person's name and CPF, for an e-CNPJ the
company's certificate, which identifies its legal representative. The principal decides when to share it, as it
would show a power of attorney; the verifier MUST treat it as personal data (LGPD), use it for this check only and
keep it no longer than the evidence of the transaction requires. `verifyPrincipalProof` returns nothing personal.

## 20. Issuance by the principal (D-37)

There is no native link between an ICP-Brasil certificate and an AI agent: the link is this format. So that it can
be produced by whoever answers for the agent, the principal MAY issue the credential itself, with no issuer service
in between. The issuer is then the holder of the e-CNPJ or e-CPF; in a delegation (section 17), the parent agent is
the issuer of its sub-agent's mandate. The reference implementation is `packages/core/src/issuance.ts`.

**Issuer.** A self-issued credential has `issuer` = `urn:kya-brasil:self`, and `verify_url` and `revocation_url` carry
the same value (there is no host to call). It has no `attestation`: the principal's signature, presented as in
section 19, is the proof.

**Mandate.** Every reserved field of section 5 MUST be stated: `actions` (non-empty), `max_per_operation`,
`max_per_day`, `currencies`, `counterparties`, `payment_instruments`, `valid_from`, `valid_until` and `delegation`.
An empty list states "any" and `delegation: null` states "may not delegate" (the field is then left out of the
mandate, as section 5 reads absence); a missing field is an error, never a default. The mandate MUST pass the
validation of section 5 and `valid_until` MUST be after the issuance time.

**What is signed.** The challenge text of section 3 (company) or 16 (person), byte for byte, with:
`issuer: urn:kya-brasil:self`, `challenge:` the `credential_id` (1 to 128 characters from `A-Z a-z 0-9 . _ : -`),
`agent:` the agent key, `cnpj:` the CNPJ (company), `mandate-sha256:` the SHA-256 of the canonical JSON (section 7,
step 2) of the mandate, and `expires:` the earliest of issuance time + the lifetime the principal chooses and
`valid_until`. The signature is a CMS/PKCS#7 SignedData over the UTF-8 bytes of that text, detached or attached
(CAdES-BES is a superset), with SHA-256 and RSA PKCS#1 v1.5 (sha256WithRSAEncryption), made by the principal's
ICP-Brasil certificate with any signer (A1 file, A3 token, HSM, cloud certificate); the certificate chain MAY be
carried in the CMS.

**Credential.** The credential of section 6, with `credential_id` as signed, `authorized_by` from the signing
certificate and `mandate_sha256` as signed, `issued_at` the issuance time, `expires_at` the earliest of the signed
`expires:` and the certificate's end of validity, `status` = `active`, and for a company `legal_name` from the
certificate's common name and `registration_status` = `NOT_CHECKED` (nobody asked the Receita Federal; a verifier
that needs it checks the CNPJ with its own source). The agent keeps the credential and the proof `{ text, cms }`.

**Issuance refuses what verification refuses.** The issuing implementation MUST verify the signature as in
section 19 before handing out the credential, and MUST refuse a delegation that section 17 would refuse (the parent
may not delegate, depth or lifetime above its policy, a mandate broader than the parent's, a parent no longer in
force). It SHOULD check the certificate's revocation (section 10) before handing out the credential.

**Verification** (`verifySelfIssuedCredential`): every check of section 19, and

1. `issuer` is `urn:kya-brasil:self`, `version` is 1, and `authorized_by.method` matches the principal's kind;
2. the text's `challenge:` line equals `credential_id`;
3. the mandate passes section 5 in normalized form;
4. `expires_at` is not after the text's `expires:` line, and the verifier's clock is from `issued_at` to `expires_at`
   with `status` = `active`.

The certificate's revocation is checked as in section 19.

**Status.** There is no issuer to ask: the credential's status is the certificate's (CRL) and its expiry. A principal
that wants to withdraw a self-issued credential before it expires revokes the certificate, so it SHOULD choose short
lifetimes. This is the trade-off of issuing without a service; a principal that wants revocation of single
credentials uses an issuer (sections 6 and 10).

## 21. Co-signature by a legal representative

Whoever holds a company's e-CNPJ can sign the text of section 20, whether or not they represent the company (the
Alloy model finds this: the e-CNPJ proves possession of the certificate, not the power to bind the company). A
self-issued company credential MAY therefore carry co-signatures by its legal representatives. The reference
implementation is `packages/core/src/cosign.ts` (`addCosignature`, `verifyCompanyWill`).

**What is signed.** Each co-signature is a CMS/PKCS#7 SignedData, as in section 20, by a natural person's e-CPF
(section 16) over the SAME bytes the e-CNPJ signed (the proof's `text`). An e-CNPJ is not a co-signer.

**Where it travels.** Additive to /v1, and following section 12 (the credential never contains the CPF or name of a
natural person acting for a company):

- the credential gains `cosignatures`: a list of `{ method: "icp-brasil-e-cpf", certificate_sha256, issuer,
  signed_at, not_after }`, one per co-signer, with no CPF and no name;
- the proof (section 19, `KYA-Principal-Proof`) gains `cosignatures`: the list of co-signature CMS (base64 DER). They
  carry the representatives' certificates, so they reach the verifier, which needs the CPF to match it; like the
  principal's CMS, an issuer MUST NOT store them.

**Who represents the company** comes from one or both of two sources, and at least one is required:

- the verifier's input `representatives`: a function from the CNPJ to the CPFs of its legal representatives (the
  QSA, from the verifier's own source). The core never calls the Receita Federal;
- with `acceptCertificateResponsible: true`, the person responsible named in the e-CNPJ itself: the CPF in its
  otherName 2.16.76.1.3.4 (DOC-ICP-04: birth date `ddmmaaaa`, then the 11-digit CPF), which the registration
  authority checks against the company's acts at issuance. No list is needed. It rests on the e-CNPJ being revoked
  when that person stops representing the company (Alloy: `ResponsibleCoSignatureSound` holds,
  `ResponsibleCoSignatureLeft` is the expected counterexample). It names one person: attorneys-in-fact, joint
  signature and powers still need the list.

**Verification** (`verifyCompanyWill`): the credential is accepted as the company's will only when

1. it passes section 20 (`verifySelfIssuedCredential`), else `COMPANY_SIGNATURE_INVALID`;
2. it carries at least one co-signature, else `NO_COSIGNATURE`;
3. every co-signature in the proof verifies over the proof's text (else `COSIGNATURE_TEXT_MISMATCH`) with an e-CPF in
   force at the verifier's clock and chained to the anchors (else `COSIGNER_CERTIFICATE_INVALID`), and the proof's
   co-signatures and the credential's `cosignatures` name the same certificates (else `COSIGNATURE_NOT_RECORDED`);
4. at least `minCosigners` (default 1) distinct CPFs read from those certificates are among the representatives
   (none: `COSIGNER_NOT_REPRESENTATIVE`; some but fewer: `INSUFFICIENT_COSIGNERS`).

The result carries the certificate hash of each co-signer, why it counted (`basis`: `representatives` or
`ecnpj_responsible`) and what its CRL check needs (section 10), never the CPF.
The revocation of the e-CPF certificates is checked by the verifier, as for the principal's certificate.
