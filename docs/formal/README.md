# Formal model and conformance

`mandate.als` is an Alloy 6 model of the mandate (SPEC section 5), delegation (section 17), the cascade from
the credential's status (section 18) and, since D-37, issuance of delegations (section 20). It mirrors
`checkAction`, `isMandateSubset`, `checkFreshAction` and `buildDelegation` in `@kya-brasil/core`, one predicate per
rule, and states the model's properties as assertions.

`conformance.als` asks Alloy for instances with a known answer: mandate pairs that are or are not contained in
one another, and actions that a mandate does or does not allow. Besides the overall yes/no cases, there is one
command per rule that breaks only that rule. `generate-vectors.py` turns the instances into
`docs/vectors/mandate-conformance.json`, and `packages/core/src/conformance.test.ts` checks that the library
gives the same answer for every vector.

## Run

With the Alloy 6 analyzer (`org.alloytools.alloy.dist.jar`, release v6.2.0, from
https://github.com/AlloyTools/org.alloytools.alloy/releases) and Java 17 or later:

```sh
java -jar org.alloytools.alloy.dist.jar exec -f -o out-checks docs/formal/mandate.als
java -jar org.alloytools.alloy.dist.jar exec -q -f -r 60 -t xml -o out docs/formal/conformance.als
python3 -I docs/formal/generate-vectors.py   # reads out/, writes docs/vectors/mandate-conformance.json
pnpm --filter @kya-brasil/core test
```

## Results (Alloy 6.2.0, SAT4J)

The literal output of the analyzer for the three models and for the mutation check is in `results-2026-11.txt`,
so the chain model → command → output → vectors → library test can be audited without installing Alloy.

| Command | Scope | Result |
| --- | --- | --- |
| `check NonAmplification` | 5, 5-bit Int | no counterexample |
| `check SubsetTransitive` | 5, 5-bit Int | no counterexample |
| `check ChainNonAmplification` | 4, 5-bit Int, sequences up to 4 | no counterexample |
| `check Cascade` | 4, 5-bit Int, sequences up to 4 | no counterexample |
| `check IssuanceMatchesVerification` | 4, 5-bit Int, sequences up to 4 | no counterexample |
| `check IssuedChainNonAmplification` | 4, 5-bit Int, sequences up to 4 | no counterexample |
| `check NoPermissionNoIssue` | 5, 5-bit Int | no counterexample |
| `run ProperDelegation` | 4, 5-bit Int, sequences up to 4 | instance found (the model is not vacuous) |

A check with no counterexample supports the property up to its scope; it is not a proof for unbounded sizes.

Three of the seven assertions hold by construction and are kept as consistency checks of the definitions, not as
theorems: `Cascade` (`permitted` requires `inForce`), `IssuanceMatchesVerification` (the link condition of `chainOk`
is `issuable`, as the two library functions call the same subset check) and `NoPermissionNoIssue` (first conjunct
of `issuable`). The mutation below shows it: with the ceiling comparison dropped from `subset`, `NonAmplification`,
`ChainNonAmplification` and `IssuedChainNonAmplification` find counterexamples while those three stay UNSAT. The
guarantee that a revoked credential is refused lives in `checkFreshAction` and in the property tests.

`verifyDelegationChain` also refuses a link that is expired, issued in the future or outliving the link above it;
the model has no time on links, so "verifies iff issuable" holds for the fields modelled. Those checks only refuse,
never accept more, so the non-amplification assertions are unaffected.

Conformance: 1,320 vectors (60 per command), and the library agrees with the model on all of them.

## Issuance (D-37)

Issuance needed one change to the model: whether a mandate may delegate at all (`deleg`, the library's
`mandate.delegation`). The library already required it, at issuance (`prepareDelegation`) and at verification
(`verifyDelegationChain`); the model did not represent it. With it:

- `subset` gains `subDeleg` (a child may delegate only if its parent may), with its own single-rule command
  `SubsetNoDeleg`, and `chainOk` requires every link's parent to allow delegation;
- `issuable[p, c]` (= `buildDelegation` succeeds) is `some p.deleg and subset[p, c]`;
- `IssuanceMatchesVerification`: a chain verifies exactly when every link was issuable. `IssuedChainNonAmplification`:
  a chain built only by issuance never allows what the signed mandate refuses. `NoPermissionNoIssue`: a mandate that
  may not delegate issues nothing below it.

The commands `IssueYes`, `IssueNo`, `IssueNoPermission` and `IssueBroader` give 240 issuance vectors;
`conformance.test.ts` calls `buildDelegation` on each. Because issuance requires every risk field and the model
leaves some out, the test fills in the child only fields that cannot change the answer (lists whose absence
already means "any" or "no delegation", and restrictions neither mandate sets). The depth and lifetime of a
`delegation` are fixed per role (parent 3 levels and 3600 s, child 1 level and 600 s) so they never decide the
answer; they stay outside the model.

One difference was found by the property tests (`issuance.test.ts`), outside the model's scope: issuance refuses a
delegation shorter than 60 s (`DELEGATION_MIN_TTL_SECONDS`) and `verifyDelegationChain` does not check that
minimum. Issuance is stricter there, never looser.

## Mutation checks

The checks and tests were run against deliberately broken versions to confirm that they detect defects:

| Mutation | Detected by |
| --- | --- |
| Model: the subset rule no longer compares ceilings | Alloy finds counterexamples to `NonAmplification` and `ChainNonAmplification` |
| Library: a delegated mandate may have a ceiling up to 3 times the parent's | `SubsetNoCeiling` vectors; property tests P1 |
| Library: the per-operation ceiling ignores the currency | `AllowsNoCeiling` vectors |

With only the overall yes/no commands, the first library mutation went undetected, because those instances
usually break several rules at once. The single-rule commands were added for that reason.

## Adversarial vectors (H4)

`adversarial.als` opens `threats.als` and asks for instances in which the verifier's rule, as implemented, must
answer in a known way: four replay commands (the same signed request twice inside its window; again after it
expired; presented before its creation beyond the skew; exactly at the edges of the window) and five freshness
commands (fresh CRL not listing the certificate; stale CRL; fresh CRL listing it; the residual window, revoked
after `thisUpdate`; a CRL exactly `MAXAGE` old). `generate-adversarial.py` writes 20 instances of each, plus six
hand-written cases outside the model's facts (lifetime above the maximum, expiry before creation, replay across the
skew, replay then expiry, stale by one second, revoked at `thisUpdate`), to `docs/vectors/adversarial-v1.json`
(326 vectors: 180 replay and freshness, 140 co-signature, 6 by hand). Replay vectors use 1 model unit = 100 s, so the model's SKEW 3 and MAXLIFE 6 are the 300 s and 600 s
defaults of `createKyaAuth`; freshness vectors use 1 unit = 1 h, MAXAGE 3 = 10 800 s.

```sh
java -jar org.alloytools.alloy.dist.jar exec -q -f -r 20 -t xml -o out-adversarial docs/formal/adversarial.als
python3 -I docs/formal/generate-adversarial.py
pnpm --filter @kya-brasil/core test          # src/adversarial.test.ts: checkFreshness on every freshness vector
pnpm --filter @kya-brasil/agent-tools test   # src/adversarial.test.ts: one signed request presented at each time
```

Result on 7 Nov 2026 (Alloy 6.2.0): every command SAT; the libraries answer as the model on all 326 vectors, with
the expected error code on each refusal (`KYA_REQUEST_REPLAYED`, `KYA_SIGNATURE_EXPIRED`,
`KYA_SIGNATURE_NOT_YET_VALID`, `KYA_SIGNATURE_TTL`). The co-signature and issuer-unavailability sections of
`threats.als`: the co-signature section has seven commands and 140 vectors (listed co-signer, not listed, other text,
absent, the e-CNPJ's responsible with no list, and the two trust assumptions the library cannot see, a stale list and
a lent e-CPF, which it must accept), replayed by `packages/core/src/adversarial-cosign.test.ts` against
`verifyCompanyWill`; the HTTP verifier exposes the check as the opt-in `offline.companyWill` of `createKyaAuth`
(`packages/agent-tools/src/offline-cosign.test.ts`). The issuer-unavailability section still has no vectors: it needs
a fake issuer.

What the model cannot produce, the certificate itself, is covered by `docs/vectors/adversarial-certificate.json`
and `packages/core/src/adversarial-certificate.test.ts`: twenty-three constructions on a test PKI generated at run time
(impostor CRL under the AC's name, CRL from another AC, stale CRL, flipped byte in a listed serial or in the
signature, truncated CRL, random bytes, RSA-PSS as an algorithm outside the verifier's set; e-CNPJ under an
unknown root, expired or not yet valid, e-CPF instead of e-CNPJ, CNPJ mismatch, wrong text, no anchors, random
bytes; and, since Resolução CG ICP-Brasil 211/2024, an e-CNPJ naming the A3 policy, accepted, and an electronic seal
in software and in hardware, the second with the CNPJ only in the DN, both refused), each with the error code the
library must return. All twenty-three pass.

## What the model leaves out

The daily ceiling (same rule as the per-operation ceiling, with `spent_today` added), wildcard counterparties
(checked by the property tests instead), payment instruments (same subset shape as currencies), the depth
and lifetime limits of delegation (they only shorten chains), and the signature itself (CMS, chain, the signed text:
checked by the round-trip and tampering tests and by `docs/vectors/self-issued-v1.json`).

## Threat model (pre-project §2.1)

`threats.als` is a separate module for threats that `mandate.als` does not cover: replay, the certificate holder versus the company's representatives, and issuer unavailability. For each one it states the
product's current rule, the property one would want, and a mitigation. A counterexample to a current-rule check is
expected: it records a limitation of the product, not a bug in the model. Time is scaled down: 3 units stand for
the 300 s allowed for a creation time in the future, and 6 for the 600 s maximum lifetime (SPEC §14).

```
java -jar org.alloytools.alloy.dist.jar exec -f -o out-threats docs/formal/threats.als
```

| Command | Result | Reading |
|---|---|---|
| `check NoReplayToday` | counterexample (expected) | The verifier keeps no nonce cache, so the same signed request is accepted twice inside its window (iv). |
| `check NoReplayWithMemory` | UNSAT, holds | If the verifier remembers each accepted request until it expires, it accepts that request at most once. |
| `check NoReplayShortMemory` | counterexample (expected) | Remembering a request for only 2 units, less than the window, still lets a replay through. The memory must last until the request expires. |
| `run AcceptsWithMemory` | SAT | Sanity check: with that memory, the verifier still accepts requests. |
| `check IssuanceImpliesCompanyWill` | counterexample (expected) | Whoever holds the e-CNPJ obtains a credential, even if they do not represent the company. The product checks the certificate, never who operates it, and it does not read the QSA (ii-b). |
| `check CoSignedImpliesCompanyWill` | UNSAT, holds | Under the proposal (a co-signature with the e-CPF of a representative listed in the QSA), it holds by construction. Its strength rests on the verifier knowing the representatives. |
| `run AccountantWithCoSignature` | SAT | Sanity check: the proposal still admits an accountant who holds the certificate, with a representative co-signing. |
| `check NoReplayImplemented` | UNSAT, holds | The replay cache as implemented in agent-tools 0.13.0 (`replayCache`: key = the signed request text, entry kept until the request's own `expires`, evicted by the verifier's clock) accepts each request at most once. |
| `check NoReplayClockDrift` | counterexample (expected) | A store that evicts by a clock 2 units ahead of the verifier's forgets a request the window still accepts; hence `seen(key, expiresAt, now)` receives the verifier's clock. |
| `run ImplementedAccepts` | SAT | Sanity check: the implemented cache still accepts distinct requests. |
| `check CoSignatureSound` | UNSAT, holds | Co-signature design: a second CMS over the same challenge text by an e-CPF whose CPF is in the verifier's `representatives(cnpj)` list. If the list is accurate and each e-CPF is operated by its owner, acceptance implies a real representative agreed to this mandate. |
| `check CoSignatureStaleList` | counterexample (expected) | With a stale list (someone no longer in the QSA still listed), the property fails: the list is a trust assumption. |
| `check CoSignatureLentECpf` | counterexample (expected) | With an e-CPF operated by someone else (lent token, copied A1), it fails: the residual risk moves to the representative's own certificate. |
| `check CoSignatureNeedsSameText` | counterexample (expected) | A verifier that does not require the co-signed text to equal the challenge accepts a co-signature taken from another mandate. |
| `check NoCoSignatureNoCompanyWill` | UNSAT, holds | Without a co-signature the credential is never accepted as the company's will, whoever operates the e-CNPJ. |
| `run AccountantCoSigned` | SAT | Sanity check: an accountant operating the e-CNPJ, with a listed representative co-signing, is accepted. |
| `check ResponsibleCoSignatureSound` | UNSAT, holds | Co-signature by the person responsible named in the e-CNPJ (otherName 2.16.76.1.3.4), with no list from the verifier: if that person still represents the company and each e-CPF is operated by its owner, acceptance implies a real representative agreed to this mandate. |
| `check ResponsibleCoSignatureLeft` | counterexample (expected) | If the responsible left the company and the e-CNPJ was not revoked, the property fails: the trust moves to the e-CNPJ's revocation. |
| `check NoCoSignatureNoResponsibleWill` | UNSAT, holds | With this rule too, the e-CNPJ alone is never the company's will. |
| `run AccountantResponsibleCoSigned` | SAT | Sanity check: an accountant operating the e-CNPJ, with the responsible it names co-signing, is accepted with no list. |
| `check IssuerDownFailsClosed` | UNSAT, holds | With the hosted issuer down, online-only mode (and the `issuerFallback` path for requests without the credential) refuses: 502, fail closed. |
| `check OfflineIndependentOfIssuer` | UNSAT, holds | Offline mode with the credential presented gives the same answer with the issuer up or down. |
| `check NoStaleRevokedAccepted` | UNSAT, holds | Offline, with the freshness policy (CRL at most `MAXAGE` old), a certificate revoked `MAXAGE` or more ago is never accepted. |
| `check NoStaleRevokedWithoutPolicy` | counterexample (expected) | Without the freshness policy, an old CRL lets a long-revoked certificate through. |
| `check NoRevokedAcceptedOffline` | counterexample (expected) | The residual window: a certificate revoked after the CRL was issued, less than `MAXAGE` ago, is accepted. The policy bounds the exposure; it does not remove it. |
| `run IssuerDownOfflineStillAccepts` | SAT | With the issuer down, an offline verifier accepts a presented credential with a fresh CRL while an online-only verifier refuses the same one at the same time. |

Scopes: replay commands 4 with 5-bit Int (times kept in 0..10 in every replay section, so `plus`/`minus` cannot wrap; the
bound was added to the first section on 7 Nov 2026 and every result stayed the same), co-signature
commands 5, issuer-unavailability commands 4 with 5-bit Int and `MAXAGE` = 3.

Notes on what the new parts mirror. The replay cache records only after the request fully verified (a forged request
neither fills the cache nor burns a genuine key) and refuses when its memory is full of live entries; both only
remove acceptances and are left out of the model. The co-signature is a design being implemented in the core; the
model fixes its acceptance rule (same text, listed CPF) and shows its two trust assumptions. In the product the
freshness policy is applied by `check()` / `allowed()` (`checkFreshAction`), not by `authenticate`, which takes the
CRL the caller's `certificateStatus` returns; "accepts" in the model is the action decision.

## Company mandate signed by a representative (D-43)

`representative.als` is a separate module, with its own signatures, so that `threats.als` and the vectors generated
from it stay as they are. It models the form a company mandate takes once the company has no signature certificate
(Resolução CG ICP-Brasil 211/2024, from 3 March 2029; SPEC section 22): one CMS by a natural person's e-CPF, accepted
only when the verifier has a list of representatives and the signer's CPF is in it.

```
java -jar org.alloytools.alloy.dist.jar exec -f -o out-representative docs/formal/representative.als
```

| Command | Result | Reading |
|---|---|---|
| `check RepresentativeSound` | UNSAT, holds | With an accurate list and e-CPFs operated by their owners, acceptance implies that a real representative agreed to this mandate. |
| `check RepresentativeStaleList` | counterexample (expected) | Someone who left the company is still in the verifier's list. |
| `check RepresentativeLentECpf` | counterexample (expected) | An e-CPF operated by someone else. With no e-CNPJ there is no second signature: this certificate is the only one between the company and the mandate. |
| `check RepresentativeNeedsSameText` | counterexample (expected) | A verifier that does not compare the signed text with the challenge accepts a signature of another text. |
| `check NoListNoAcceptance` | UNSAT, by construction | With no list nothing is accepted: a consistency check of the rule, not a theorem. |
| `check SealNeverAccepted` | UNSAT, by construction | A mandate signed with the company's seal is never accepted. |
| `check SealAsSignatureIsCompanyWill` | counterexample (expected) | A verifier that took the seal for a signature would accept whoever holds it: the flaw `IssuanceImpliesCompanyWill` found for the e-CNPJ. |
| `run RepresentativeAccepts` | SAT | Sanity check: the rule accepts something, and it is the company's will. |

The library's counterpart is `packages/core/src/cosign.test.ts` (issuance, refusal with no list, list that
does not name the signer or fails, method swapped after signing, counting with co-signatures) and three constructions
of the certificate catalogue. No vectors are generated from this module yet.

