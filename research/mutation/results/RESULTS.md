# Mutation testing of @kya-brasil/core

@kya-brasil/core 0.22.1 (commit 8aff7ea665d5), Stryker 10.1.1, the library's own tests and vectors.
The score is the share of mutants a test detected (killed or timed out) among those that could be detected.

| File | Mutants | Killed | Timed out | Survived | No test reaches it | Score (%) |
|---|---:|---:|---:|---:|---:|---:|
| `src/attestation.ts` | 189 | 177 | 2 | 9 | 1 | 94.7 |
| `src/challenge.ts` | 160 | 129 | 0 | 22 | 9 | 80.6 |
| `src/cnpj.ts` | 68 | 64 | 0 | 4 | 0 | 94.1 |
| `src/cosign.ts` | 263 | 174 | 0 | 71 | 18 | 66.2 |
| `src/credential.ts` | 129 | 102 | 0 | 21 | 6 | 79.1 |
| `src/crl-der.ts` | 363 | 234 | 5 | 99 | 25 | 65.8 |
| `src/delegation.ts` | 414 | 386 | 0 | 26 | 2 | 93.2 |
| `src/freshness.ts` | 459 | 438 | 0 | 19 | 2 | 95.4 |
| `src/icp-brasil.ts` | 333 | 219 | 0 | 89 | 25 | 65.8 |
| `src/issuance.ts` | 651 | 433 | 0 | 164 | 54 | 66.5 |
| `src/mandate.ts` | 534 | 482 | 0 | 52 | 0 | 90.3 |
| `src/person.ts` | 135 | 93 | 1 | 35 | 6 | 69.6 |
| `src/principal-proof.ts` | 255 | 159 | 0 | 90 | 6 | 62.4 |
| `src/revocation.ts` | 250 | 207 | 0 | 39 | 4 | 82.8 |
| `src/timestamp.ts` | 244 | 168 | 0 | 63 | 13 | 68.9 |
| **All** | 4447 | 3465 | 8 | 803 | 171 | 78.1 |
