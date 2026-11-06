# Research

The research behind KYA Brasil: three pre-registered hypotheses, the experiments and instruments that test them,
the formal model, and the paper's artifact. The library and the hosted issuer do not depend on anything here.

Pre-registration: [osf.io/t59kv](https://osf.io/t59kv) (under embargo until November 2027), written before the
12 months of CRL collection that the confirmatory tests use. The text is in
[docs/research/pedido-iti-osf-zenodo.md](../docs/research/pedido-iti-osf-zenodo.md). Until that collection ends,
every measurement here is **exploratory**.

## Hypotheses

| | Hypothesis | Tested with | Pass criterion |
| --- | --- | --- | --- |
| H1 | The library issues and verifies mandates as the Alloy model does: non-amplification in delegation, revocation cascade, issuance equivalent to verification, replay protection, company will only with a listed representative's co-signature | [docs/formal](../docs/formal) (Alloy 6 model and checks) and the conformance vectors [docs/vectors](../docs/vectors), run against `@kya-brasil/core` | no unexpected counterexample, no divergence between model and library |
| H2 | A freshness policy proportional to the action's value (maximum status age = L / (value × λ)) lies on the Pareto frontier of expected loss vs. status fetches, against fixed deadlines and value tiers | [freshness-sim](freshness-sim) (Monte Carlo, fixed seed) with the rate, delay and hourly profile measured on ICP-Brasil CRLs | position on the frontier, 95% bootstrap intervals over the collection months |
| H3 | Independent developers verify a mandate from the documentation alone, without changing the library | [study](study) (protocol and analysis) and the kit [`@kya-brasil/study-kit`](../packages/study-kit) | integration without changing the library; time to the first correct verification, changes requested, time until a revocation takes effect |

H2 is read with the measurement first: the CRL data show where the risk of an offline verification lies (the
time an AC takes to register a revocation, not the CRL cadence), and the freshness policy is a consequence of that
risk. The pre-registered test and criterion do not change.

## Complementary evaluations (exploratory)

Not hypotheses and not in the pre-registration; reported apart from H1–H3 and labelled exploratory.

| Evaluation | What | Status |
| --- | --- | --- |
| Legal validation | two specialists rate the preliminary legal reading (mandate, representation of the company, good-faith third party, delegation, LGPD) on a fixed set of questions | dossier ready; no answers yet |
| Demand | short conversations with those who would receive agents' actions (marketplaces, fintechs, ERPs): would they require the credential, and what would stop them | not started |
| gov.br, considered and excluded | Login Único is open only to government systems (D-13); the gov.br advanced signature carries less weight between private parties than the qualified ICP-Brasil signature, so the design keeps the qualified one | decided |

## Where things are

| Folder | What | Feeds |
| --- | --- | --- |
| [freshness-sim](freshness-sim) | freshness-policy simulation, measured parameters, sensitivity to the rate and the action value | H2, paper |
| [crl-compat](crl-compat) | the current ICP-Brasil CRLs verified with OpenSSL, Go, Python `cryptography`, `@peculiar/x509`, PKI.js, node-forge and the core; weekly on GitHub Actions | paper (library compatibility) |
| [bench](bench) | latency and size of issuance, verification, co-signature, request signing and CRLs, on a test PKI | paper (performance) |
| [study](study) | H3 protocol, ethics note and `analyze.py` for the kit's reports | H3 |
| [paper](paper) | `figuras.py`: the paper's figures and every number its text cites, from the results above | paper |
| [../docs/formal](../docs/formal) | Alloy models (`mandate.als`, `threats.als`, `conformance.als`) and the vector generator | H1 |
| [../docs/vectors](../docs/vectors) | conformance and test vectors, also run by the core's tests | H1, SPEC |
| [../packages/study-kit](../packages/study-kit) | `kya-study`, the case-study instrument, published on npm | H3 |
| [../artefato](../artefato) | the paper's artifact guide (SBSeg format): one command per claim | paper |

The CRL revocation data come from the separate collector [kya-icp](https://github.com/celfons/kya-icp).

## Data and code DOIs

| What | DOI |
| --- | --- |
| This repository (library, models, experiments) | [10.5281/zenodo.23973230](https://doi.org/10.5281/zenodo.23973230) |
| kya-icp collector (code) | [10.5281/zenodo.23973109](https://doi.org/10.5281/zenodo.23973109) |
| kya-icp CRL dataset, version 2 | [10.5281/zenodo.23985090](https://doi.org/10.5281/zenodo.23985090) |

## Reproducing

[artefato/README.md](../artefato/README.md) lists the environment and one command per claim of the paper. Each
folder above has its own README with its command and its expected output. Nothing here uses a real certificate
or key: every PKI is generated for the run and marked TEST ONLY.
