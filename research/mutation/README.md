# research/mutation

How many faults injected in `@kya-brasil/core` the library's own tests and vectors catch. Stryker changes one
thing at a time in the source (a comparison, a condition, a constant, a call) and runs the tests that reach it. A
mutant that no test notices is a rule that could be loosened without anyone seeing.

Fifteen files are mutated: the mandate and its containment, delegation, issuance, the principal's proof, the
ICP-Brasil signature, the CRL reader and its verification, freshness, the co-signature, the time-stamp, the
attestation, the credential, the challenge, the person's proof and the CNPJ. Tests and test data are not.

```bash
pnpm --filter @kya-brasil/research-mutation all
```

Five batches, each well under two hours on four cores (about two hours in all). Stryker runs in place, in
`packages/core`: it restores the files when it ends, and after an interrupted run `git checkout packages/core/src`
does. `data/` is not committed. `results/results.json` and `results/RESULTS.md` are, and list every survivor by
file, line and kind.

## What the run of 12 November 2026 found

Core 0.22.0, Stryker 10.1.1: 69.4% of 4 447 mutants detected, from 62.4% (`principal-proof.ts`) to 82.8%
(`revocation.ts`). About a third of the survivors change only the text of a message. The others are logic.

In the two files that hold containment and delegation, the survivors were edges no test reached: an amount equal
to the ceiling, the depth a child may delegate (`max_depth - 1` could become `max_depth + 1`), the payment
instruments of a delegated mandate, the first and last instant of a window, a link as long as the policy allows,
and the limits of the schema (32 actions, 16 currencies, 200 counterparties, 20 instruments, 8 192 and 2 048 bytes).
The vectors generated from the Alloy model did not reach them either: the model has small integers and no schema.
`mandate-boundaries.test.ts` and a new block in `delegation.test.ts` reach them. Every new test passed on the
first run: the rules were right and untested at the edge.

| File | Before | After |
|---|---:|---:|
| `src/mandate.ts` | 67.2% | 90.3% |
| `src/delegation.ts` | 66.4% | 93.2% |
| `src/freshness.ts` | 74.7% | 95.4% |
| `src/cosign.ts` | 66.2% | 95.1% |
| `src/crl-der.ts` | 65.8% | 95.0% |
| `src/attestation.ts` | 75.7% | 94.7% |
| `src/cnpj.ts` | 64.7% | 94.1% |
| `src/principal-proof.ts` | 62.4% | 93.7% |
| `src/revocation.ts` | 82.8% | 86.4% |
| All fifteen | 69.4% | 84.0% |

The same was then done for the freshness policy (`freshness-boundaries.test.ts`), for the CNPJ, which had no test
of its own (`cnpj.test.ts`), for the CPF digits, the surrogates of the canonical JSON and the reasons a signed
answer gives (`identity-boundaries.test.ts`), for the DER reader of CRLs, on lists built byte by byte
(`crl-der.test.ts`), for the revocation rules (`revocation.test.ts`), and for the principal's proof and the
co-signature, check by check (`cosign.test.ts`). No new test found a fault in the library.

Six files were left as measured, between 64.6% and 80.6%: `icp-brasil.ts`, `issuance.ts`, `timestamp.ts`,
`person.ts`, `credential.ts` and `challenge.ts`. Their survivors are mostly in the validation of the issuer's own
input and in paths that need a time-stamping authority or a certificate of an unusual shape to reach; the
verification they feed is covered by the vectors and by `research/differential`. The count of mutants is 4 489
since core 0.22.2 added code to `icp-brasil.ts`.

## What this does not show

A detected mutant shows that a test fails when the rule changes. It does not show that the rule is the right one:
that is what the model and its vectors are for. And what survives is not all a gap: some mutants are equivalent
to the original, and they are not separated here.
