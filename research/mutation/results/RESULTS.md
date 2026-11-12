# Mutation testing of @kya-brasil/core

@kya-brasil/core 0.22.1 (commit 1c44c6f1fdd2), Stryker 10.1.1, the library's own tests and vectors.
The score is the share of mutants a test detected (killed or timed out) among those that could be detected.

| File | Mutants | Killed | Timed out | Survived | No test reaches it | Score (%) |
|---|---:|---:|---:|---:|---:|---:|
| `src/attestation.ts` | 189 | 141 | 2 | 23 | 23 | 75.7 |
| `src/challenge.ts` | 160 | 128 | 0 | 23 | 9 | 80 |
| `src/cnpj.ts` | 68 | 44 | 0 | 13 | 11 | 64.7 |
| `src/cosign.ts` | 263 | 174 | 0 | 71 | 18 | 66.2 |
| `src/credential.ts` | 129 | 102 | 0 | 21 | 6 | 79.1 |
| `src/crl-der.ts` | 363 | 234 | 5 | 99 | 25 | 65.8 |
| `src/delegation.ts` | 414 | 386 | 0 | 26 | 2 | 93.2 |
| `src/freshness.ts` | 459 | 343 | 0 | 101 | 15 | 74.7 |
| `src/icp-brasil.ts` | 333 | 219 | 0 | 89 | 25 | 65.8 |
| `src/issuance.ts` | 651 | 433 | 0 | 164 | 54 | 66.5 |
| `src/mandate.ts` | 534 | 482 | 0 | 52 | 0 | 90.3 |
| `src/person.ts` | 135 | 91 | 1 | 37 | 6 | 68.1 |
| `src/principal-proof.ts` | 255 | 159 | 0 | 90 | 6 | 62.4 |
| `src/revocation.ts` | 250 | 207 | 0 | 39 | 4 | 82.8 |
| `src/timestamp.ts` | 244 | 168 | 0 | 63 | 13 | 68.9 |
| **All** | 4447 | 3311 | 8 | 911 | 217 | 74.6 |
