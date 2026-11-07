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

**CRLs the `cryptography` library cannot decode.** `fetch_measured.py` skips, with a warning and an `error` field in
`measured.json`, any CRL that `load_der_x509_crl` refuses; on 7 Nov 2026 that is only the AC Certisign OM-BR list
(Ed448 signature whose AlgorithmIdentifier the library rejects, 7 entries). The collector's own header parser still
counts it in the aggregates.

**Sensitivity factors from the data.** `fetch_factors.py` writes `data/factors.json` with three multiples of the
measured rate taken from the collection itself: the peak month over the mean month, the flow rate over the stock
rate, and the highest relative hazard of one AC (its share of new entries over its share of the stock, a proxy
since the ITI keeps no per-AC counts). `sensitivity.py` adds the largest of them to its grid (1, 3, 10, 30, 100),
so the paper can cite the observed bound and present the rest as a stress test. On 7 Nov 2026: 1.17, 1.17 and 2.8.

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

## Value and rate from Pix and credit card (`value_scale.py`, `fetch_pix_cnae.py`, `fetch_pix_rate.py`, `fetch_cards.py`)

There is no public data on what agents buy or how often. Agents pay mostly by Pix and by credit card, the two means
with the easiest programmatic access, and the Central Bank publishes both. Each scenario takes the value AND the rate
of actions from its own open data (D-41):

- **Pix (main scenario):** payments between companies of different owners, by receiver CNAE section, size, MEI and
  form of initiation (`data/pix_cnae.json`, last 12 months): mean R$ 3,168.91; Pix paid per paying company
  (`data/pix_rate.json`, by the payer's municipality): 77.42 a month, 0.10603 an hour;
- **company credit card** (Empresarial and Corporativo, `data/cards.json`, 20253 to 20262): mean purchase
  R$ 281.37; 6.44 purchases a month per active card, 0.00882 an hour.

The value keeps the log-normal shape with sigma = 1.6 (about 80% of the value in the top 20% of actions), above the
lower bound of 1.489 that the spread of the 516 CNAE groups' means gives; the median is set so that the
mean matches. The rates are human baselines; an agent 10 and 100 times as active is a variation. Each run simulates
about the same number of actions (credentials scaled inversely to the rate, `credentials_for`).

## Robustness to the unmeasured parameters (`scenarios.py`)

`scenarios.py` (offline, a few minutes on 4 cores): the two base scenarios, then one parameter at a time on Pix
(sigma from the lower bound to 2.0; 10 and 100 times the rate) and on the card (100 times the rate). Writes
`scenarios.json`. Per 1,000 actions:

| Scenario | Median (R$) | sigma | Actions/h | Floor (R$) | Proportional L=0.01: fetches | loss (R$) | Fixed 12 h: fetches | loss (R$) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| principal | 881 | 1.6 | 0.1060 | 13.18 | 368 | 14.59 | 442 | 16.03 |
| cartão | 78 | 1.6 | 0.0088 | 1.17 | 830 | 1.28 | 905 | 1.21 |
| sigma no limite inferior | 1046 | 1.489 | 0.1060 | 13.19 | 374 | 14.70 | 442 | 16.04 |
| sigma 2,0 | 429 | 2.0 | 0.1060 | 13.14 | 347 | 14.19 | 442 | 15.96 |
| Pix, 10 vezes o ritmo | 881 | 1.6 | 1.0603 | 13.08 | 104 | 14.56 | 74 | 17.82 |
| Pix, 100 vezes o ritmo | 881 | 1.6 | 10.6030 | 13.31 | 30 | 14.21 | 8 | 18.36 |
| cartão, 100 vezes o ritmo | 78 | 1.6 | 0.8820 | 1.16 | 50 | 1.75 | 87 | 1.58 |

## Sensitivity to the rate

`sensitivity.py` (seed 20261105, offline, about 10 minutes on 4 cores) repeats the measured comparison from 1x to
100x the measured revocation rate, which is a floor and counts every revocation, not only compromises, in the Pix and
card scenarios, each with its own rate. For each scenario it reports the proportional policy's gain over a fixed
deadline that makes the same number of fetches (fixed-deadline loss interpolated on log fetches), as a share of the
loss a verifier can avoid at all, that is, above the always-fetch floor that comes from the AC's own delay. Writes
`sensitivity.json`.

| Rate (x measured) | Pix: share removed | gain (R$/1,000) | floor (R$/1,000) | Card: share removed |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 70% | 3.32 | 13.18 | 27% |
| 3 | 79% | 5.77 | 39.54 | 50% |
| 10 | 85% | 7.30 | 131.70 | 71% |
| 30 | 89% | 7.11 | 394.34 | 82% |
| 100 | 91% | 4.27 | 1305.57 | 88% |

The result depends on the product of value and rate. Even at 100x, the avoidable loss is small next to the floor:
the AC's working hours bound freshness.

## Rate from the flow of new entries (`fetch_flow.py`)

`python3 -I fetch_flow.py` writes `data/flow.json`: for every end-user CRL, the entries in the current list, the
share registered on weekdays 8:00-17:59 (Brasília), the declared validity, the new entries the collector saw
appear during its own window, and the measured delays; and, in total, new entries per hour summed over the lists,
divided by the national active count (ITI). This is the rate the paper will prefer at the confirmatory cut: the
rate from the *stock* of entries a CRL holds is biased because ACs drop expired certificates (older months are
undercounted, more so for ACs with short-lived certificates), while the *flow* the collector observes is not. The
denominator is still the national count, so it stays a lower bound for coverage. The paper's per-list table
(`kya-paper`, `figs/por-lista.tex`) comes from the same file.

## The fraud-ruler L (`simulate.fraud_ruler_L`)

The sweep also runs the proportional policy with the L that the Pix fraud yardstick gives: the share of Pix value
accepted as fraud (`data/pix_fraud.json`) applied to the mean value of a Pix payment between companies
(`value_scale.py`), R$ 0.71 on the November 2026 data. It is the paper's main setting (`scenarios.json`,
`proportional_Lfraude`). At the measured rate, L / (v × λ) exceeds the 24 h cap for every action below about
R$ 107,000, so that setting behaves like a fixed 24 h deadline and only starts to differentiate actions at high
values or at 10 to 100 times the rate; the L = 0.01 rows above are the stingy end of the same dial.

## Where the policy matters, and how large the loss is (exploratory)

- **Tail.** `scenarios.py` also reports the loss on the top 1% of actions by value. In the Pix scenario, the
  proportional policy with L = 0.03 makes fewer fetches than a fixed 12 h deadline and loses on those actions about as
  little as always fetching; the fixed deadline loses about a fifth more.
- **Refusals.** `simulate_availability.py` uses the Pix and card scenarios: fixed deadlines of 15 min and 1 h refuse
  most legitimate actions, the proportional policy and the 12 h deadline about 1% to 2%.
- **Yardstick.** `fetch_pix_fraud.py` (`data/pix_fraud.json`): contested Pix accepted as fraud over the last 12
  months with statistics, as a share of all Pix value, to compare with the simulated expected loss.
- **Reasons.** `fetch_reasons.py` (`data/reasons.json`, needs `cryptography`): reason codes in the current end-user
  CRLs, to bound the share of key compromise in the revocation rate.

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
