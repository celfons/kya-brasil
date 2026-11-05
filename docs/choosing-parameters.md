# Choosing the risk parameters

The library has no defaults for risk: whoever issues or verifies a mandate states every value. This page explains
each choice and gives reference values measured in ICP-Brasil. Infrastructure is also yours: run the verifier, and
optionally the reference issuer (`apps/worker`, see `docs/SELF-HOSTING.md`), wherever you prefer.

## When issuing a mandate (`buildMandate`)

| Field | What it limits | How to choose |
| --- | --- | --- |
| `actions` | what the agent may do | list only the actions it needs; `[]` means any action |
| `max_per_operation` | the loss of one bad action | the largest single payment you would accept losing |
| `max_per_day` | the loss before anyone notices | what you can lose in a day; the verifier supplies `spent_today` |
| `counterparties`, `currencies`, `payment_instruments` | where money can go | as narrow as the use allows; `[]` means any |
| `valid_from` / `valid_until`, credential lifetime | how long a leaked mandate stays usable | short. A self-issued credential (`urn:kya-brasil:self`) cannot be revoked alone: it dies at expiry or with the certificate. If you need to revoke a single credential early, issue it through the reference issuer instead |
| `delegation` | sub-agents | `null` unless needed; then the smallest `max_depth` and `max_ttl_seconds` |

The ceilings are the only defence that holds when the agent's key is stolen or the model misbehaves: status
freshness does not help there (`research/freshness-sim`).

## When verifying (`freshnessPolicy`)

| Field | Meaning | Reference |
| --- | --- | --- |
| `max_expected_loss` | the expected loss you accept per action (L) | your risk appetite, in the payment currency |
| `revocation_rate_per_hour.certificate` | λ, how often a certificate is revoked | measured in ICP-Brasil: about 2.8 × 10⁻⁷ per hour (0.24% per year). It counts every revocation, so it is a ceiling on key compromise and a floor on coverage (`research/freshness-sim`, dataset DOI 10.5281/zenodo.23985090) |
| `max_age_seconds` | cap on the age of status evidence, whatever the amount | a CRL is reissued every 1 to 6 hours; a cap of a few hours keeps the CRL useful without refetching on every action |
| `require` | which evidence must be present | `["certificate"]` offline; add `"credential"` when an issuer signs status |
| `max_clock_skew_seconds` | tolerance between clocks | a few minutes |
| `unvalued_action` | actions with no amount | `"refuse"`, or `"ceiling"` with `action_risk_value` per action name |
| `past_valid_until` | a CRL past its `nextUpdate` | `"refuse"` |

The allowed age is `min(max_age_seconds, L / (amount × λ))`: larger amounts need fresher status. With the measured
λ, the simulation shows the proportional rule on the Pareto frontier at few status fetches. Whatever the policy, a
residual window remains: revocation in ICP-Brasil happens mostly on weekdays in office hours, about 15 hours on
average between a revocation request and the CRL that shows it (`research/freshness-sim/README.md`). Short credential
lifetimes and low ceilings are what cover that window.

## Optional checks

- **Replay:** pass `replayCache` to `createKyaAuth`; entries are kept until each request's own expiry.
- **Company will:** require a co-signature (`verifyCompanyWill`) and supply `representatives(cnpj)` from a source you
  trust. The public CNPJ open data masks the partner's CPF (one mask matches 1,000 valid CPFs) and has no partners for
  MEI/EI companies, so it can filter but not prove (kya-icp `analysis/qsa`).
