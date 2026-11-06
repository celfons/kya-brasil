# Freshness policies: simulation

Monte Carlo comparison of the policies a verifier can use to decide how old status evidence may be before it
accepts an agent's action offline (SPEC section 18). The run is reproducible:

```sh
python3 -I simulate.py   # numpy only; writes results.json (about 2.5 minutes)
```

**The parameters are hypothetical.** The rate of revocation (λ = 1e-5 per hour, about 8.4% a year) and the
traffic (2 actions per hour per agent, log-normal values with median R$ 200) are placeholders in `simulate.py`; the
measured runs below take the value scale from Pix (`value_scale.py`). They were placeholders for the values
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

## Value scale from Pix (`value_scale.py`, `fetch_pix_cnae.py`)

There is no public data on what agents buy, so the measured comparison (`simulate_measured.py`), the sensitivity and
the robustness runs take the scale of the action values from the Central Bank's Pix open data:

- **B2B (main):** payments between companies of different owners, by receiver CNAE section, size, MEI and form of
  initiation (`fetch_pix_cnae.py`, `data/pix_cnae.json`, last 12 months): mean R$ 3,168.91 per transaction;
- **P2B:** payments from people to companies (`fetch_pix.py`, `data/pix.json`): mean R$ 110.68.

The value keeps the log-normal shape with sigma = 1.6 (about 80% of the value in the top 20% of actions), and the median
is set so that the mean matches Pix (B2B: R$ 881.08). The CNAE data have no value bands, only a mean per group; the spread
of log(group mean) across the 516 groups, weighted by count, is sigma >= 1.489, a lower bound for the whole
distribution. The traffic (2 actions per hour per credential) has no public source.

## Robustness to the unmeasured parameters (`scenarios.py`)

`scenarios.py` (offline, a few minutes on 4 cores) changes one parameter at a time from the main scenario, with the
measured rate and cadence: sigma from the lower bound to 2.0, and 0.2 to 20 actions per hour (credentials scaled so
each run simulates about the same number of actions); plus the P2B scale and the former placeholder median of R$ 200.
Writes `scenarios.json`. Per 1,000 actions:

| Scenario | Median (R$) | sigma | Actions/h | Floor (R$) | Proportional L=0.01: fetches | loss (R$) | Fixed 12 h: fetches | loss (R$) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| principal | 881 | 1.6 | 2.0 | 13.20 | 75 | 14.52 | 40 | 18.09 |
| sigma no limite inferior | 1046 | 1.489 | 2.0 | 13.21 | 76 | 14.63 | 40 | 18.10 |
| sigma 2,0 | 429 | 2.0 | 2.0 | 13.14 | 70 | 14.15 | 40 | 18.00 |
| 0,2 ação/h | 881 | 1.6 | 0.2 | 13.22 | 257 | 14.81 | 296 | 16.84 |
| 20 ações/h | 881 | 1.6 | 20.0 | 13.36 | 21 | 14.12 | 4 | 18.47 |
| Pix P2B | 31 | 1.6 | 2.0 | 0.46 | 21 | 0.76 | 40 | 0.63 |
| mediana hipotética R$ 200 | 200 | 1.6 | 2.0 | 3.00 | 34 | 3.90 | 40 | 4.11 |

## Sensitivity to the rate

`sensitivity.py` (seed 20261105, offline, about 10 minutes on 4 cores) repeats the measured comparison from 1x to
100x the measured revocation rate, which is a floor and counts every revocation, not only compromises, at the Pix B2B
and P2B scales. For each scenario it reports the proportional policy's gain over a fixed deadline that makes the same
number of fetches (fixed-deadline loss interpolated on log fetches), as a share of the loss a verifier can avoid at
all, that is, above the always-fetch floor that comes from the AC's own delay. Writes `sensitivity.json`.

| Rate (x measured) | B2B: share removed | gain (R$/1,000) | floor (R$/1,000) | P2B: share removed |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 46% | 1.14 | 13.20 | 12% |
| 3 | 59% | 2.27 | 39.59 | 27% |
| 10 | 69% | 4.00 | 131.87 | 36% |
| 30 | 76% | 5.88 | 394.85 | 46% |
| 100 | 83% | 7.65 | 1307.26 | 61% |

The result depends on the product of value and rate. Even at 100x, the avoidable loss is small next to the floor:
the AC's working hours bound freshness.

## Exploratory: the cost of failing closed, with Pix values (`simulate_availability.py`)

Not part of the pre-registered H2 test, which stays as above. Two additions, from public data:

- **Values.** Besides the placeholder median of R$ 200, the scale of the log-normal is set from the Central Bank's
  Pix statistics (`fetch_pix.py`, `data/pix.json`): over the last 12 months, the mean Pix payment from company to
  company (B2B, including transfers between companies of the same owner) was R$ 5,306 and from person to company
  (P2B) R$ 111. Pix payments are not agents' purchases; they are
  the closest public figure for what a company pays or is paid per transaction.
- **A third axis: legitimate actions refused.** Evidence age is counted from the CRL's `thisUpdate`, as the library's
  freshness check does. At each moment a verifier polling hourly holds the latest CRL the collector had obtained
  (`fetch_availability.py`, `data/availability.json`). It refuses a legitimate action when that CRL is past its
  `nextUpdate`, or when the policy asks for evidence younger than any CRL it can get.

```sh
python3 -I fetch_pix.py && python3 -I fetch_availability.py   # network; write data/
python3 -I simulate_availability.py                            # offline; writes results_availability.json (~4 min)
```

**Effective availability** (first collection window, about 23 h, 6 end-user CRLs still issued): a fresh CRL was
available 99% of the time, weighting by entries. The three Certisign CRLs, valid for only 1 h, were past their
`nextUpdate` 12% to 20% of the time for an hourly poller, in gaps of at most 13 min: a verifier must poll more often
than the CRL's validity. The CRL held was 0.8 h old at the median.

**Pix B2B values** (per 1,000 legitimate actions; refusal rates carry about ±1 of Monte Carlo noise):

| Policy | Fetches | Expected loss (R$) | Refused |
| --- | ---: | ---: | ---: |
| Always fetch (accepts the CRL in force) | 1000.0 | 22.20 | 10.0 |
| Fixed 0.25 h | 666.9 | 22.26 | 990.2 |
| Fixed 1 h | 333.7 | 22.68 | 460.9 |
| Fixed 2 h | 200.3 | 23.35 | 62.3 |
| Fixed 6 h | 77.2 | 26.15 | 10.5 |
| Proportional, L = 0.01 | 98.3 | 23.66 | 34.3 |
| Proportional, L = 0.03 | 54.9 | 25.72 | 14.6 |
| Value tiers, medium | 362.8 | 22.39 | 502.0 |

What changes with this axis:

- **Strict policies are not feasible offline.** No CRL is younger than its own publication cadence, so a policy that
  asks for evidence younger than about an hour refuses most legitimate actions (46% to 99% at 1 h or less) to save at
  most a few percent of the loss.
- **The feasible region is the lenient one** (fixed 4 h or more, proportional, loose tiers): about 1% refused, the
  floor set by expired CRLs. Within it, the proportional policy reaches the loss of a fixed window with about 30% fewer
  fetches (L = 0.03 against fixed 6 h, L = 0.1 against fixed 12 h), at a similar or slightly higher refusal rate.
- **Real values scale the stakes.** With B2B Pix values the loss floor that no policy removes is R$ 22 per 1,000
  actions, about seven times the placeholder scenario; with P2B values it is R$ 0.46.

The window is the first day of collection; the figures will be re-run as it grows.

## Exploratory: the exposure window with the measured publication delay (`simulate_measured_delay.py`)

`simulate_measured.py`, whose figures the paper cites, models the time from the AC registering a revocation to a CRL
that lists it as the wait for the next CRL (phase uniform over the reissue interval) plus a dissemination of U(0, 4) h,
the DOC-ICP-05 4.9.8 maximum. The collector now measures both (`fetch_delays.py`, `data/delays.json`):

| Measured (first collection window) | n | Mean | Median | p95 | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| Registration by the AC → thisUpdate of the first CRL listing it | 166 | 0.72 h | 0.59 h | 2.65 h | 3.84 h |
| thisUpdate → CRL obtained by an hourly poller (upper bound of dissemination) | 144 | 0.29 h | 0.20 h | 0.80 h | 0.91 h |

```sh
python3 -I fetch_delays.py && python3 -I simulate_measured_delay.py   # writes results_measured_delay.json (~1 min)
```

Exposure window, from compromise to a disseminated CRL listing the revocation:

| Model | Mean | Median | p95 | Business hours | Off hours | Friday 19h |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Paper (next CRL + U(0, 4) h) | 15.45 h | 9.33 h | 53.8 h | 3.52 h | 20.5 h | 48.2 h |
| Measured delay + measured dissemination (upper bound) | 14.33 h | 8.22 h | 52.7 h | 2.42 h | 19.4 h | 47.3 h |
| Measured delay, no dissemination (lower bound) | 13.87 h | 7.75 h | 52.3 h | 1.96 h | 18.9 h | 46.8 h |

Replacing the regulatory maximum with what the ACs actually do shortens the mean window by about 1.1 to 1.6 h; about
14 of its 15 hours remain. Publishing and disseminating the CRL take under an hour; the rest is the wait for the AC to
register the revocation in its working hours. With the measured delay, "always fetch" leaves R$ 2.79 per 1,000 actions
that no policy removes (R$ 3.01 in the paper's model), and the ranking of the policies does not change.
