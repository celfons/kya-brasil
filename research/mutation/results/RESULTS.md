# Mutation testing of @kya-brasil/core

@kya-brasil/core 0.22.2 (commit 9bf0445a2459), Stryker 10.1.1, the library's own tests and vectors.
The score is the share of mutants a test detected (killed or timed out) among those that could be detected.

| File | Mutants | Killed | Timed out | Survived | No test reaches it | Score (%) |
|---|---:|---:|---:|---:|---:|---:|
| `src/attestation.ts` | 189 | 177 | 2 | 9 | 1 | 94.7 |
| `src/challenge.ts` | 160 | 129 | 0 | 22 | 9 | 80.6 |
| `src/cnpj.ts` | 68 | 64 | 0 | 4 | 0 | 94.1 |
| `src/cosign.ts` | 263 | 250 | 0 | 12 | 1 | 95.1 |
| `src/credential.ts` | 129 | 102 | 0 | 21 | 6 | 79.1 |
| `src/crl-der.ts` | 363 | 340 | 5 | 17 | 1 | 95 |
| `src/delegation.ts` | 414 | 386 | 0 | 26 | 2 | 93.2 |
| `src/freshness.ts` | 459 | 438 | 0 | 19 | 2 | 95.4 |
| `src/icp-brasil.ts` | 376 | 243 | 0 | 109 | 24 | 64.6 |
| `src/issuance.ts` | 650 | 435 | 0 | 165 | 50 | 66.9 |
| `src/mandate.ts` | 534 | 482 | 0 | 52 | 0 | 90.3 |
| `src/person.ts` | 135 | 93 | 1 | 35 | 6 | 69.6 |
| `src/principal-proof.ts` | 255 | 239 | 0 | 14 | 2 | 93.7 |
| `src/revocation.ts` | 250 | 216 | 0 | 30 | 4 | 86.4 |
| `src/timestamp.ts` | 244 | 167 | 0 | 64 | 13 | 68.4 |
| **All** | 4489 | 3761 | 8 | 599 | 121 | 84 |
