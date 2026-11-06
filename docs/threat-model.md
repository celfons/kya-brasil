# Threat model coverage

This is section 2.1 of the research pre-proposal, linked to the product. For each threat, the table gives:

- **Defense:** what the product does;
- **Evidence:** what shows the defense works;
- **Residual risk:** what remains open.

The Alloy commands are in `docs/formal/mandate.als` and `docs/formal/threats.als` (results in `docs/formal/README.md`). The tests are in `packages/*/src/*.test.ts`; when a test is cited by title, the quoted text is the exact title of the `it(...)`.

**Kinds of evidence:**

- **Alloy:** property with no counterexample in the declared scope; an expected counterexample records a limitation.
- **Vectors:** the 1,320 cases in `docs/vectors/mandate-conformance.json`, run against the library.
- **Tests:** unit and property tests.
- **Data:** measurement of ICP-Brasil CRLs (`research/freshness-sim`; series from the `kya-icp` collector, DOI 10.5281/zenodo.24011370, see `CITATION.cff`).

## Summary

| # | Threat | Defense | Evidence | Status |
|---|---|---|---|---|
| 1 | Theft of the agent's key | Mandate limits; short validity; credential revocation; short delegation | Vectors, tests | Mitigated, risk limited to the mandate |
| 2 | Compromise of the principal's key | Revocation in the CRL; freshness policy; revocation effect by reason | Alloy, tests, data | Mitigated, with a measured residual window |
| 3 | Use of the e-CNPJ by someone who does not represent the company | Co-signature by the e-CPF of a listed representative | Alloy, tests | Mitigated if the verifier requires it; relies on the QSA list |
| 4 | Compromised hosted issuer | Principal proof verified only against ICP-Brasil; issuance by the holder itself | Tests, vectors | Mitigated in offline mode |
| 5 | Hosted issuer unavailable | Offline mode; online mode fails closed | Alloy, tests | Mitigated in offline mode |
| 6 | Replay | Short validity window; request cache until expiry | Alloy, tests | Mitigated if the verifier turns on the cache |
| 7 | Power amplification through delegation | Delegated mandate must be a subset; limited depth and duration | Alloy, vectors, property tests | Mitigated |
| 8 | Acceptance of stale status | Maximum status age proportional to value; expired CRL refused | Alloy, tests, data, simulation | Limited, not eliminated |

## Detail

### 1. Theft of the agent's key

- **Defense:** whoever steals the key can only do what the mandate allows:
  - per-operation and per-day ceilings;
  - listed currencies, counterparties and payment instruments (SPEC §5);
  - short credential validity (SPEC §6), capped by the certificate's `notAfter` (D-35);
  - immediate revocation of the credential by the holder, when there is a hosted issuer (SPEC §10);
  - short-lived delegations (SPEC §17).
- **Evidence:**
  - vectors `Allows*` and `SubsetNo*` (commands in `docs/vectors/mandate-conformance.json`);
  - `packages/core/src/mandate.test.ts`, `packages/core/src/delegation.test.ts`;
  - `packages/agent-tools/src/offline.test.ts`: "refuses a tampered mandate, a wrong agent key and a missing proof or credential".
- **Residual risk:**
  - **Self-issued credential:** has no individual revocation. Only short validity and certificate revocation apply (SPEC §20).
  - **Daily ceiling:** `max_per_day` depends on the `spent_today` supplied by the verifier.

### 2. Compromise of the principal's key (e-CNPJ or e-CPF)

- **Defense:**
  - the verifier checks the certificate's CRL (`checkRevocation`);
  - the maximum accepted CRL age depends on the action's value (SPEC §18);
  - the effect of revocation on mandates already issued is the verifier's policy, by revocation reason (D-36);
  - an authorization signed after the revocation, or after the `invalidityDate`, is never kept.
- **Evidence:**
  - Alloy: `NoStaleRevokedAccepted` (`threats.als`) holds; `Cascade` (`mandate.als`, P3: a credential not in force allows nothing, whatever the chain) holds;
  - tests: `packages/core/src/revocation.test.ts` (CRL; effect by reason, D-36: "applies the caller's policy: revoke on compromise or no reason, suspend on hold, keep a later benign replacement" and "never keeps what was signed after the suspected compromise, or without a date to compare") and `packages/core/src/freshness.test.ts`;
  - `packages/agent-tools/src/offline.test.ts`: "refuses untrusted anchors, an expired credential and a revoked certificate".
  - measured data: 94% of revocations on business days, from 8:00 to 18:00; mean window of 15.5 h between the revocation request and the CRL (simulation).
- **Residual risk:**
  - the interval between the compromise and the revocation request cannot be observed;
  - certificates revoked after the last accepted CRL pass within the window (`NoRevokedAcceptedOffline`, expected counterexample);
  - up to core 0.19.0, `verifyCrl` refused CRLs with more than about 1,240 entries (asn1js ASN.1 node limit), such as the one from AC SERPRO RFB v5 (~77,000 entries): the verifier failed closed (502) for every e-CNPJ from that CA. Fixed in 0.19.1 (own DER reader, limited to 64 MiB and 2,000,000 entries; tested with a CRL of 200,000 entries); found by the benchmark (`research/bench`).

### 3. Use of the e-CNPJ by someone who does not represent the company

The typical case is the accountant who keeps the company's A1.

- **Defense:**
  - co-signature, with an e-CPF, of the same signed text (`addCosignature`);
  - `verifyCompanyWill` only accepts if the e-CPF's CPF is in `representatives(cnpj)`, the verifier's list (SPEC §21).
- **Evidence:**
  - Alloy (`threats.als`): `IssuanceImpliesCompanyWill` gives a counterexample without co-signature (the problem); `CoSignatureSound` and `NoCoSignatureNoCompanyWill` hold;
  - tests: `packages/core/src/cosign.test.ts` ("refused: the co-signer's CPF is not a representative", "refused: no co-signature" and the others in the block "co-signature by a legal representative (section 21)").
- **Residual risk:**
  - outdated list of representatives (`CoSignatureStaleList`);
  - list without the full CPF: the CNPJ open data (full dataset of Oct. 2026, measured for the paper) publishes the partner's CPF masked (6 of 11 digits visible; the first 3 and the 2 check digits hidden), which leaves 1,000 valid CPFs per mask. Name, mask and company nearly identify the partner (266 collisions nationwide), but do not prove that the e-CPF holder is not someone with the same name. Coverage: outside MEI and EI, 85.9% of active companies have an individual partner who is administrator, director, president or managing partner (99.5% of LTDAs, 99.3% of SAs); MEI and EI (62% of active companies) have no partner list; 5.6 million partners have no administrative power; powers, joint signature and attorneys-in-fact are not listed; a change takes 1 to 2 months to appear. With this source the verifier can only filter (name, mask and qualification 05, 10, 16 or 49, with a tolerance of ~2 months); the list that `representatives(cnpj)` asks for must come from a source with the full CPF: the e-CNPJ itself, whose otherName 2.16.76.1.3.4 carries the CPF of the person responsible before the Receita (DOC-ICP-04) and which can sign the statement of who the co-signers are, or a contracted lookup (Receita/Serpro, Junta Comercial);
  - lent e-CPF (`CoSignatureLentECpf`);
  - a verifier that does not require the co-signature: the defense is optional.

### 4. Compromised hosted issuer

- **Defense:**
  - the agent presents the principal proof, the signed text plus the CMS (SPEC §19), and the verifier checks it against ICP-Brasil, without trusting the issuer's key;
  - or the holder issues with no issuer at all (SPEC §20, `urn:kya-brasil:self`).
- **Evidence:**
  - tests: `packages/core/src/principal-proof.test.ts` ("refuses a credential whose mandate is not the one signed", "refuses a proof for another agent or another issuer") and `packages/core/src/issuance.test.ts` (block "issuance: tampering is refused");
  - vectors: `docs/vectors/self-issued-v1.json`;
  - `packages/agent-tools/src/offline.test.ts`: "refuses an issuer it does not list and a credential edited after the issuer signed it".
- **Residual risk:** without the principal proof, online mode trusts the issuer.

### 5. Hosted issuer unavailable

- **Defense:**
  - in offline mode (`createKyaAuth({ offline })`), the verifier does not call the issuer;
  - in online mode, unavailability gives 502 and nothing is accepted.
- **Evidence:**
  - Alloy (`threats.als`): `check OfflineIndependentOfIssuer` and `check IssuerDownFailsClosed` hold; `run IssuerDownOfflineStillAccepts` is satisfiable;
  - `packages/agent-tools/src/offline.test.ts`, with a mocked `fetch` checked as never called: "accepts the request with no call to fetch and evaluates the mandate locally" and "accepts it with the issuer's public key and the proof, without calling the issuer".
- **Residual risk:** the availability of the CRL itself, which is measured by the collector (`kya-icp`).

### 6. Request replay

- **Defense:**
  - request signed with `created` and `expires`, valid for at most 600 s (SPEC §14);
  - `replayCache` keeps the SHA-256 of the signed text until the request's own expiry and refuses the repeat with `401 KYA_REQUEST_REPLAYED`.
- **Evidence:**
  - Alloy (`threats.als`): `NoReplayToday` gives a counterexample without a cache; `NoReplayImplemented` holds; `NoReplayShortMemory` and `NoReplayClockDrift` show why the memory lasts until expiry and uses the verifier's clock;
  - `packages/agent-tools/src/auth.test.ts`, block "replay cache (opt-in)": "refuses the same signed request twice, accepts different requests, and nothing changes without the option", "keeps entries until the request expires, then evicts them", "fails closed when full or when the store errors, and needs a bounded lifetime";
  - `packages/agent-tools/src/offline.test.ts`: "refuses a replayed request at the verifier's clock; past its expiry the window refuses it";
  - `examples/quickstart/agent-and-verifier-offline.mjs` (runs in CI).
- **Residual risk:** the defense only works with the cache turned on; without it, the 600 s window stays open.

### 7. Power amplification through delegation

- **Defense:**
  - each delegated mandate must be a subset of the mandate above it: ceilings, currencies, counterparties and actions;
  - limited depth and duration;
  - only those with permission can delegate (SPEC §17, D-37).
- **Evidence:**
  - Alloy (`mandate.als`): `NonAmplification`, `ChainNonAmplification`, `IssuedChainNonAmplification` and `NoPermissionNoIssue`;
  - conformance vectors (`SubsetNo*`, `IssueBroader`, `IssueNoPermission`);
  - property tests P1–P4 in `packages/core/src/properties.test.ts` (P1 "non-amplification" is the one about delegation);
  - mutations recorded in the "Mutation checks" section of `docs/formal/README.md`.
- **Residual risk:** the minimum duration of 60 s is not enforced when verifying the chain; issuance is stricter.

### 8. Acceptance of stale status

- **Defense:**
  - maximum status age of L / (value × λ), with a ceiling (SPEC §18);
  - refusal of an expired CRL (`pastNextUpdate: "refuse"`), of a missing proof, of an invalid clock and of a proof dated in the future.
- **Evidence:**
  - Alloy (`threats.als`): `NoStaleRevokedAccepted` holds; `NoStaleRevokedWithoutPolicy` gives a counterexample without the policy;
  - `packages/core/src/freshness.test.ts`: "refuses missing evidence for a required kind", "refuses evidence dated in the future beyond the caller's clock skew, and accepts it within", "fails closed on another currency, a bad amount or a missing or bad clock" and "turns a CRL lookup into certificate evidence; past nextUpdate it is refused or judged by age, as the caller chose";
  - data: measured λ of about 0.24% per year;
  - simulation: Pareto frontier (`research/freshness-sim`), to be tested as H2 in the pre-registration (osf.io/t59kv).
- **Residual risk:** the policy limits exposure, it does not eliminate it; λ is a lower bound and the revocation reason is rarely published. A CRL the verifier cannot read leads to refusal (fail closed), not to acceptance of old status; up to core 0.19.0 this happened with every large CRL (see threat 2).

## Out of scope

- Compromise of a certificate authority or of the ICP-Brasil root.
- Legal validity of the mandate: this goes to the legal analysis in the pre-proposal.
- Disputing an act the agent already performed: the issuer does not record acts (D-19).
