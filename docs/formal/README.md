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

## What the model leaves out

The daily ceiling (same rule as the per-operation ceiling, with `spent_today` added), wildcard counterparties
(checked by the property tests instead), payment instruments (same subset shape as currencies), the depth
and lifetime limits of delegation (they only shorten chains), and the signature itself (CMS, chain, the signed text:
checked by the round-trip and tampering tests and by `docs/vectors/self-issued-v1.json`).
