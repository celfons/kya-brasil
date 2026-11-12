# Differential test against OpenSSL

Cut of 2026-11-07T21:24:36.190Z, @kya-brasil/core 0.22.1 (commit 8c7eed33d09d), OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024). Seed 20261112.

## Entries of the CRLs of the cut

| Lists | Entries | With reason | Lists that differ |
|---:|---:|---:|---:|
| 100 | 340588 | 53398 | 0 |

## Mutated CRLs

200 mutants of each list (one bit, one header byte, a truncation or four bytes in a row).

| Mutants | Core parsed | Core refused (DerError) | Core failed otherwise | Slowest (ms) |
|---:|---:|---:|---:|---:|
| 20000 | 11198 | 8802 | 0 | 192 |

Mutants of lists up to 300000 bytes were also given to OpenSSL.

| Compared | Both accept | Both refuse | Only the core accepts | Only OpenSSL accepts | Dates differ |
|---:|---:|---:|---:|---:|---:|
| 18200 | 8096 | 6404 | 2112 | 1588 | 0 |

With the certificate of the AC, taken from `anchors/icp-brasil.pem`, the signature of each mutant was verified by
both, for the 76 lists whose AC is there and whose original both verify.

| Mutants | Both verify | Both refuse | Only the core verifies | Only OpenSSL verifies |
|---:|---:|---:|---:|---:|
| 15200 | 12 | 15183 | 0 | 5 |

## CMS signature of the self-issued vector

| Case | Core | OpenSSL |
|---|---|---|
| The vector | accepts | accepts |
| The same signature over another text | refuses | refuses |

2000 mutants of the signature, one bit each.

| Both accept | Both refuse | Only the core accepts | Only OpenSSL accepts |
|---:|---:|---:|---:|
| 278 | 1301 | 25 | 396 |
