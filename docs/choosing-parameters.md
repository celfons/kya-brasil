# How to choose the risk parameters

The library has no default risk values: whoever issues or verifies a mandate supplies every value. This page
explains each choice and gives reference values measured in ICP-Brasil. The infrastructure is yours too: run the
verifier wherever you prefer.

## When issuing a mandate (`buildMandate`)

| Field | What it limits | How to choose |
| --- | --- | --- |
| `actions` | what the agent can do | only the actions it needs; `[]` means any action |
| `max_per_operation` | the loss from one wrongful action | the largest single payment you would accept losing |
| `max_per_day` | the loss until someone notices | how much you can lose in a day; the verifier supplies `spent_today` |
| `counterparties`, `currencies`, `payment_instruments` | where the money can go | as narrow as the use allows; `[]` means any |
| `valid_from` / `valid_until`, credential validity | how long a leaked mandate stays usable | according to your risk appetite, by the same principle as the proposed formula, `L / (value × λ)`: the higher the mandate's ceilings and the lower the tolerated loss (L), the shorter the validity. A credential issued by the holder itself (`urn:kya-brasil:self`) stops being valid only when it expires or when the certificate is revoked |
| `delegation` | subagents | `null`, unless you need it; in that case, the smallest `max_depth` and the smallest `max_ttl_seconds` |

The ceilings are the only defense that works when the agent's key is stolen or the model misbehaves: status
freshness does not help in those cases (`research/freshness-sim`).

## When verifying (`freshnessPolicy`)

| Field | Meaning | Reference |
| --- | --- | --- |
| `max_expected_loss` | the expected loss you accept per action (L) | your risk appetite, in the payment currency |
| `revocation_rate_per_hour.certificate` | λ, how often a certificate is revoked | measured in ICP-Brasil: about 2.8 × 10⁻⁷ per hour (0.24% per year). It counts all revocations, so it is an upper bound for key compromise and a lower bound for coverage (`research/freshness-sim`, dataset DOI 10.5281/zenodo.23985090) |
| `max_age_seconds` | ceiling on the age of the status proof, whatever the value | the CRL is reissued every 1 to 6 hours; a ceiling of a few hours keeps the CRL useful without fetching it for every action |
| `require` | which proofs are mandatory | `["certificate"]` in offline mode; add `"credential"` when an issuer signs the status |
| `max_clock_skew_seconds` | tolerance between clocks | a few minutes |
| `unvalued_action` | actions with no value | `"refuse"`, or `"ceiling"` with `action_risk_value` per action name |
| `past_valid_until` | CRL after its `nextUpdate` | `"refuse"` |

The allowed age is `min(max_age_seconds, L / (value × λ))`: larger values require more recent status. With the
measured λ, the simulation puts the proportional rule on the Pareto frontier when there are few status lookups.
Whatever the policy, a residual window remains: in ICP-Brasil, revocation happens mostly on business days, during
business hours, and takes on average about 15 hours between the revocation request and the CRL that shows it
(`research/freshness-sim/README.md`). Short validity and low ceilings are what cover that window.

## Optional checks

- **Replay:** pass `replayCache` to `createKyaAuth`; each entry is kept until the request's own expiry.
- **Company will:** require the co-signature (`verifyCompanyWill`) and supply `representatives(cnpj)` from a
  source you trust. The CNPJ open data masks the partner's CPF (each mask matches 1,000 valid CPFs), has no
  partners for MEI and EI, and does not report signing authority limits or joint signature; it works as a filter,
  not as proof (kya-icp, `analysis/qsa`).
