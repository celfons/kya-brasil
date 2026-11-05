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

## Measured parameters (November 2026)

`fetch_measured.py` reads the public ICP-Brasil CRL collector and writes `data/weekday_hour.csv` and
`data/measured.json`; `simulate_measured.py` runs offline from those files (seed 20261105, about 5 minutes) and
writes `results_measured.json`.

```sh
python3 -I fetch_measured.py      # needs cryptography; network
python3 -I simulate_measured.py   # numpy only
```

**Inputs.**

- **Rate.** 11 end-user CRLs hold 182,907 revocations (2012 to 2026). January to October 2026 average 3,465
  a month, against 17,175,212 active certificates (ITI, 4 Nov 2026): λ = 3,465 × 12 / 17.2 M = 0.24% a year,
  2.76e-7 per hour, 36 times below the placeholder. **This is a floor**: the collector covers a few of the
  end-user ACs, and a CRL drops a certificate once it expires, so older months undercount even more. Not every
  revocation is a compromise (Certisign RFB G5: 52.5% keyCompromise; SERPRO and Soluti give no reason); the run
  counts every revocation.
- **When ACs revoke.** Revocation dates, in Brasília time: 94.0% fall on weekdays 08–18 h (29.8% of the week's
  hours), 0.8% on weekends. The model: compromise is uniform over the week; each hour-of-week slot is staffed
  with probability `w(h) / max w` from `data/weekday_hour.csv`, and the AC revokes in the first staffed slot.
- **Publication.** The collected CRLs are reissued every 30 minutes; `nextUpdate` is 1 h (Certisign) or 6 h
  (SERPRO, Soluti, Serasa). The run uses the 30 minutes and repeats with the `nextUpdate` bound; the CRL then
  takes U(0, 4) h to be published (DOC-ICP-05 4.9.8).

**Exposure window** (compromise until the revocation is in a published CRL, 30-minute reissue).

| | Hours |
| --- | ---: |
| Mean over the week | 15.5 |
| Median | 9.3 |
| p95 | 53.8 |
| Compromise in business hours (mean) | 3.5 |
| Compromise outside business hours (mean) | 20.5 |
| Compromise Friday 19 h (mean / p95) | 48.2 / 66.0 |
| Worst slot, Friday 22 h (mean) | 50.0 |
| Weekend compromise ÷ weekday compromise (mean) | 3.6× |

With the `nextUpdate` bound the mean is 18.0 h, p95 56.4 h, Friday 19 h 50.6 h, weekend ÷ weekday 3.0×. The
CRL cadence is a small part: the window is set by when the AC acts, not by how often it publishes.

**Policies** (per 1,000 actions, certificate evidence, same traffic as above).

| Policy | Fetches | Synthetic loss (R$) | Measured loss (R$) | Measured delay, λ = 1e-5 (R$) |
| --- | ---: | ---: | ---: | ---: |
| Always fetch | 1000.0 | 35.74 | 3.01 | 108.57 |
| Fixed 1 h | 333.7 | 38.13 | 3.08 | 110.90 |
| Fixed 6 h | 77.2 | 55.41 | 3.55 | 127.86 |
| Fixed 24 h | 20.8 | 118.77 | 5.25 | 189.45 |
| Proportional, L = 0.01 | 34.3 / 209.3 | 37.55 | 3.92 | 110.34 |
| Tiers, medium | 288.6 | 37.52 | 3.06 | 110.31 |

(Proportional fetch counts depend on the λ the verifier assumes: 34 under the measured λ, 209 under 1e-5.)

- The measured delay triples the loss that no verifier policy removes (R$ 108.57 against R$ 35.74 at the same
  λ): weekend and night compromises wait for Monday.
- The measured λ, a floor, cuts every loss by about 36×. The proportional policy still covers the Pareto front
  at low fetch counts, value tiers and short fixed windows at high counts.
- Under measured values a 6 h window costs R$ 0.54 per 1,000 actions over always fetching; the irreducible
  R$ 3.01 comes from the AC's working hours, which only credential evidence from the agent's issuer (no
  publication delay) or the mandate's ceilings can cover.
