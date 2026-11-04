# Formal model and conformance

`mandate.als` is an Alloy 6 model of the mandate (SPEC section 5), delegation (section 17) and the cascade from
the credential's status (section 18). It mirrors `checkAction`, `isMandateSubset` and `checkFreshAction` in
`@kya-brasil/core`, one predicate per rule, and states the model's properties as assertions.

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
python3 -I docs/formal/generate-vectors.py out docs/vectors/mandate-conformance.json
pnpm --filter @kya-brasil/core test
```

## Results (Alloy 6.2.0, SAT4J)

| Command | Scope | Result |
| --- | --- | --- |
| `check NonAmplification` | 5, 5-bit Int | no counterexample |
| `check SubsetTransitive` | 5, 5-bit Int | no counterexample |
| `check ChainNonAmplification` | 4, 5-bit Int, sequences up to 4 | no counterexample |
| `check Cascade` | 4, 5-bit Int, sequences up to 4 | no counterexample |
| `run ProperDelegation` | 4, 5-bit Int, sequences up to 4 | instance found (the model is not vacuous) |

A check with no counterexample supports the property up to its scope; it is not a proof for unbounded sizes.

Conformance: 1,020 vectors (60 per command), and the library agrees with the model on all of them.

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
(checked by the property tests instead), payment instruments (same subset shape as currencies), and the depth
and lifetime limits of delegation (they only shorten chains).
