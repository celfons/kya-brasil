# KYA Credential v1

A **KYA credential** states that a company, identified by its e-CNPJ (ICP-Brasil) certificate, declared
that an AI agent key acts on its behalf within a mandate, and that the issuer checked the company with
KYB Brasil on the dates shown. It is a JSON document signed with Ed25519 by the issuer. Anyone can
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
| Issuer | An Ed25519 signing key, published | Verifies both signatures and the company (KYB), issues, reviews daily, publishes status. |
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
   including validity dates at verification time. Issuers SHOULD check revocation (CRL or OCSP) when
   the AC publishes it; the reference implementation does not yet.
4. Record only the certificate SHA-256, subject, issuer and the signing time. The signer's CPF and any
   other personal field in the certificate MUST NOT be stored or published.

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
| `valid_from`, `valid_until` | ISO 8601 | now MUST be inside the window |

A check is only performed when both the mandate field and the query field are present. The serialized
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
  "kyb_snapshot": { "risk_level": "low", "risk_score": 5, "registration_status": "ATIVA", "active_sanctions": 0, "forced_labor": false, "federal_debt_brl": null, "active_embargoes": 0, "red_flags": [], "checked_at": "ISO 8601" },
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
- Issuance MUST be refused when the KYB check shows the company not active, with active sanctions, on the forced-labour list, or at critical risk.
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
3. **Live status**: `GET verify_url`. Accept only `status == "active"`. Verifiers that cache credentials SHOULD poll `/v1/revocations?since=` at least daily.
4. **Expiry**: `now < expires_at`.
5. **Mandate**: either evaluate section 5 locally, or request a signed verdict from the issuer (section 9) and keep it as evidence.

## 9. Verdict

`GET /v1/agents/{id}/allowed?action=&amount=&currency=&counterparty=&spent_today=` returns:

```json
{ "credential_id": "...", "status": "active", "allowed": true, "reason": "inside the mandate",
  "query": { ... }, "checks": [{ "rule": "actions", "ok": true, "detail": "..." }, ...],
  "not_evaluated": ["notes"], "checked_at": "ISO 8601", "attestation": { ... } }
```

`allowed` is true only when the live status is `active` and every performed check passed. The verdict is signed as in section 7, so the verifier can keep it as proof of what the issuer said at `checked_at`.

## 10. Revocation

The company signs, with its e-CNPJ (section 4), the text `KYA Brasil: revoke <credential_id>\n<nonce>`.
The issuer MUST set the status to `revoked` at once, record the event, and list it in
`GET /v1/revocations?since=`. Revocation is final; a new registration issues a new credential.

## 11. Daily review

The issuer MUST re-run the KYB check on every `active` or `suspended` credential at least daily, suspend
the ones that no longer clear, and reinstate suspended ones that clear again, recording each change as an event.

## 12. Privacy

Only legal-entity data is processed. The credential and the issuer's records MUST NOT contain the CPF or
the name of the natural person who holds the e-CNPJ; the certificate hash identifies the authorization.

## 13. Test vectors

`docs/vectors/credential-v1.json` contains an issuer key, a challenge with its text, a signed credential,
a signed verdict and a tampered copy of the credential that MUST fail verification. An implementation is
conformant with this document when it accepts the credential and the verdict, rejects the tampered copy,
reproduces the challenge text from its fields, and reaches the same `allowed` result for the mandate.
