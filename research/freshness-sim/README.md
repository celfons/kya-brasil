# Freshness policies: simulation

Monte Carlo comparison of the policies a verifier can use to decide how old status evidence may be before it
accepts an agent's action offline (SPEC section 18). The run is reproducible:

```sh
python3 -I simulate.py   # numpy only; writes results.json (about 2.5 minutes)
```

**The parameters are hypothetical.** The rate of revocation (λ = 1e-5 per hour, about 8.4% a year) and the
traffic (2 actions per hour per agent, log-normal values with median R$ 200) are placeholders for the values
the research will measure. The publication delay of a certificate revocation follows the maxima allowed by
DOC-ICP-05 v7.0: a CRL for end-user certificates at most every 6 hours (4.9.7.2), published at most 4 hours
after it is generated (4.9.8).

## Alternatives compared

| Policy | What decides the evidence age |
| --- | --- |
| Always fetch | none: fetch for every action |
| Fixed window | one age for every action (following the ICP-Brasil CRL cadence is the 6 h case) |
| Proportional to value | `L / (v × λ)`, capped at 24 h (the core's formula) |
| Value tiers | a few bands of value, each with its own age (PSD2-style) |

Short-lived credentials behave, for the verifier, like a fixed window equal to their lifetime, and an agent
stapling a fresh issuer-signed status behaves like always fetching, with the cost moved to the agent. Neither
needs its own run.

## Results (hypothetical parameters)

Values are per 1,000 actions: status fetches, and expected loss in R$.

**Value shape.** The top 20% of actions carry 77.7% of the value. The proportional policy with `L = 1` spends
52.9% of its fetches on that top 20%.

**Certificate evidence (ICP-Brasil CRL, with publication delay).**

| Policy | Fetches | Expected loss (R$) |
| --- | ---: | ---: |
| Always fetch | 1000.0 | 35.74 |
| Fixed 1 h | 333.8 | 38.13 |
| Fixed 6 h (ICP-Brasil cadence) | 77.3 | 55.41 |
| Proportional, L = 0.1 | 67.7 | 48.52 |
| Proportional, L = 0.01 | 209.3 | 37.55 |
| Tiers, medium | 288.2 | 37.52 |

Always fetching does not reach zero: the publication delay the rules allow leaves about R$ 36 per 1,000
actions that no verifier policy removes. Beyond about one hour of freshness, extra fetches buy little.

**Credential evidence (issuer status, no publication delay).**

| Policy | Fetches | Expected loss (R$) |
| --- | ---: | ---: |
| Always fetch | 1000.0 | 0.00 |
| Fixed 1 h | 333.8 | 2.42 |
| Fixed 6 h | 77.3 | 19.91 |
| Proportional, L = 0.1 | 68.0 | 12.85 |
| Proportional, L = 0.01 | 209.4 | 1.82 |
| Tiers, medium | 288.2 | 1.80 |

On the Pareto front (no other policy has both fewer fetches and less loss), the proportional policy covers the
whole useful range: against a fixed 6 h window it fetches 12% less and loses 35% less, against a fixed 1 h window
37% fewer fetches and 25% less loss. Value tiers join the front only at high fetch counts.

**Stolen agent key.** An attacker sends 60 actions per hour just under a R$ 5,000 per-operation ceiling, and the
compromise is detected after 12 hours.

| Policy | Loss without a daily ceiling (R$) | Loss with a R$ 20,000 daily ceiling (R$) |
| --- | ---: | ---: |
| Always fetch | 5,066,597 | 20,000 |
| Fixed 6 h | 5,935,988 | 21,510 |
| Proportional, L = 1 | 8,082,231 | 33,150 |

Freshness does not protect against a stolen key: the loss happens before anyone revokes. The proportional
policy is the worst of the three here, because the attacker picks a value that its formula treats as medium.
The daily ceiling is what bounds the loss, which is why counting and enforcing it is part of the verifier's
policy (SPEC section 18, "Daily ceilings").

**Sensitivity.** `results.json` also holds the three main policies under true rates of 1e-6 and 1e-4 per hour,
with the verifier still assuming 1e-5. Loss scales roughly with the true rate, and the ranking of the policies
does not change.
