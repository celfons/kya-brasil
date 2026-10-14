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

The issuer hands the company a one-time challenge that binds issuer, agent, CNPJ and expiry, so a
signature cannot be replayed for another company or issuer. The text MUST be exactly these six lines
joined by `\n`, no trailing newline:

```
KYA Brasil: prove this agent key acts for a company
issuer: <issuer origin>
challenge: <challenge_id, uuid>
agent: <kind>:<id>
cnpj: <14 digits>
expires: <ISO 8601 UTC>
```

The challenge MUST expire within 15 minutes and MUST be consumed on first use, successful or not.

## 4. Company proof (e-CNPJ)

The company signs the challenge text with its e-CNPJ certificate as a **detached CMS/PKCS#7 SignedData**
(RFC 5652), DER, base64. The issuer MUST:

1. Parse the CMS, require exactly one `SignerInfo`, and verify the signature over the challenge bytes.
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

Note on the otherName: ICP-Brasil encodes the CNPJ as a 14-character ASCII string in an OCTET STRING or a
PrintableString, depending on the AC; implementations SHOULD accept both and keep only the 14 digits.

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
  "authorized_by": { "method": "icp-brasil-e-cnpj", "certificate_sha256": "hex", "certificate_subject": "CN=...", "issuer": "CN=AC ...", "signed_at": "ISO 8601" },
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

- `expires_at` MUST be at most 90 days after `issued_at` and MUST NOT be later than `mandate.valid_until`.
- Issuance MUST be refused when the certificate is revoked (section 4) or when the company's registration at the Receita Federal is confirmed as other than `ATIVA`. Nothing else about the company (sanctions, debt, risk score) affects issuance or status.
- The registration check is optional and never blocks on its own failure (D-24). When the issuer has it off, `principal.registration_status` is `NOT_CHECKED`; when no source answers, `UNVERIFIED`. In both cases the credential is issued, `legal_name` comes from the e-CNPJ certificate, and the issuance response carries the reason in `warnings` (and in `kyb_warnings`, kept for v1). The daily review checks again and suspends if a later answer is not `ATIVA`. Verifiers that require a confirmed status MUST check for `ATIVA`.
- `kyb_snapshot` is kept in v1 for compatibility and is `null` in credentials issued by the reference issuer since D-23. Older credentials may carry a risk screen taken at issuance (an object with `risk_level`, `active_sanctions`, `checked_at` and similar); it never affected status and verifiers MUST NOT read it as a current assessment.
- `status` is the status **at issuance**. Later changes (suspension by the daily review, revocation, expiry) are not re-signed; they are published at `verify_url` and in the revocation list.

## 7. Signature (attestation)

1. Remove the `attestation` and `receipt` fields.
2. Canonicalize: JSON with object keys sorted lexicographically at every level, no whitespace, `undefined` members omitted, arrays in order, numbers as JavaScript `JSON.stringify` prints them.
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
3. **Live status**: `GET verify_url`. Accept only `status == "active"`. Verifiers that cache credentials SHOULD poll `/v1/revocations?since=` at least daily. When the issuer is unreachable, steps 2 and 4 still work offline but say nothing about a later suspension or revocation; accepting such a credential is the verifier's risk until `expires_at`.
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

1. **Certificate.** The CRL of the e-CNPJ that authorized the credential (section 4). A listed certificate
   revokes the credential (final), except: `certificateHold` suspends it until the entry disappears, and
   `superseded` or `cessationOfOperation` dated after the authorization change nothing (the certificate was
   replaced or retired without compromise; the signature stands). An unreachable CRL changes nothing that day.
2. **Registration.** The company's status at the Receita Federal: not `ATIVA` suspends the credential;
   `ATIVA` again reinstates it.

ERC-8004 credentials are also suspended when the on-chain wallet changes (section 2); that suspension is
not lifted by the review.

## 12. Privacy

Only legal-entity data is processed. The credential and the issuer's records MUST NOT contain the CPF or
the name of the natural person who holds the e-CNPJ; the certificate hash identifies the authorization.

## 13. Company: inventory and events

The issuer does not record what agents do (acts were removed in 0.5.0, D-19). `max_per_day` is evaluated with
the `spent_today` the verifier supplies. What the issuer offers the company instead:

**Requests.** Text signed with the e-CNPJ (section 4, including the revocation check), lines joined by `\n`:

```
KYA Brasil: <verb> <cnpj, 14 digits>
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

Request text, lines joined by `\n`:

```
KYA Brasil: request
credential: <credential_id>
method: <METHOD, upper case>
url: <scheme>://<host, lower case>[:port if not default]<path>[?query]
created: <KYA-Created>
expires: <KYA-Expires>
content-sha256: <KYA-Content-SHA256 | ->
```

The verifier MUST reject a signature whose `created` is more than 300 s in the future or whose `expires` has
passed, MUST recompute the body hash when a body is present, MUST verify the signature with the credential's
agent key (`agent.id`, or `agent.wallet` for `erc8004`), and MUST accept only `status == "active"`. It MAY
cache the credential for a short time (60 s in the reference client) and SHOULD honour `/v1/revocations`.
This profile is deliberately simple; an RFC 9421 (HTTP Message Signatures) binding for `web-bot-auth` keys
is planned and will carry the same `KYA-Credential` header.

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
