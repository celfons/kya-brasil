"""
EXPLORATORY: the cost of failing closed, and the freshness policies with Pix values. Adds a third axis to the
comparison of simulate_measured.py: legitimate actions REFUSED because no CRL fresh enough was available.

    python3 -I simulate_availability.py   # numpy only; reads data/availability.json, data/pix.json, data/measured.json;
                                         # writes results_availability.json

Model:
  - evidence age is counted from the CRL's thisUpdate (as the library's freshness check does), not from the fetch;
  - at time t a verifier polling as often as the collector (hourly) holds the latest version uploaded before t
    (data/availability.json, from fetch_availability.py). It is STALE when t is past its nextUpdate: a verifier that
    refuses expired CRLs (pastNextUpdate: "refuse") must refuse every action then;
  - a legitimate action of value v at t is refused when the CRL is stale, or when the policy asks for evidence younger
    than the CRL it can get (age > max_age(v)). "Consultar sempre" fetches before every action and accepts the latest
    CRL in force: it is refused only when the CRL is stale;
  - t is uniform over each source's observed window; sources weigh by their entries (as in simulate_measured.py);
  - values are log-normal with the shape of simulate.py (sigma 1.6). Three scales: the placeholder median R$ 200, and
    the Pix scales of value_scale.py: B2B between different owners (data/pix_cnae.json, the main scale) and P2B
    (data/pix.json), with the median set so that the log-normal mean matches;
  - fetches and expected loss come from the same sweep as simulate_measured.py, re-run with the Pix scales.
The window is as long as the collection so far, so every figure here is exploratory and will be re-run.
"""
import json
import math
import os
import sys
from datetime import datetime

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script directory out of sys.path
import simulate as S  # noqa: E402
import provenance  # noqa: E402
import value_scale as V  # noqa: E402
import simulate_measured as M  # noqa: E402

DATA = os.path.join(HERE, "data")
SEED = 20261106
STEP_MIN = 1  # sampling step over the observed window
SAMPLES = 200_000  # Monte Carlo draws per policy setting for the refusal rate


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() / 3600.0  # hours


def load_json(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return json.load(f)


def timeline(src, end_h):
    """Age (h) of the CRL held, and whether it is stale, at every STEP_MIN over the source's observed window."""
    v = [(ts(x["uploaded"]), ts(x["this_update"])) for x in src["versions"]]
    v.sort()
    up = np.array([a for a, _ in v])
    tu = np.array([b for _, b in v])
    t = np.arange(up[0], end_h, STEP_MIN / 60.0)
    i = np.searchsorted(up, t, side="right") - 1
    age = t - tu[i]
    stale = age > src["validity_h"]
    return age, stale


def longest_run(mask, step_h):
    best = cur = 0
    for x in mask:
        cur = cur + 1 if x else 0
        best = max(best, cur)
    return best * step_h


def availability(av):
    end_h = ts(av["summary_generated_at"])
    per, ages, stales, weights = {}, [], [], []
    for sid, src in av["sources"].items():
        age, stale = timeline(src, end_h)
        per[sid] = {"ac": src["ac"], "validity_h": src["validity_h"], "window_h": round(len(age) * STEP_MIN / 60, 1),
                    "versions": len(src["versions"]), "available_share": round(1 - float(stale.mean()), 4),
                    "longest_stale_h": round(longest_run(stale, STEP_MIN / 60), 2),
                    "age_median_h": round(float(np.median(age)), 2), "age_p95_h": round(float(np.quantile(age, 0.95)), 2)}
        ages.append(age)
        stales.append(stale)
        weights.append(np.full(age.size, src["entries"] / age.size))
    age = np.concatenate(ages)
    stale = np.concatenate(stales)
    w = np.concatenate(weights)
    w = w / w.sum()
    pooled = {"available_share": round(1 - float(np.sum(w * stale)), 4),
              "age_median_h": round(float(np.median(age)), 2)}
    return per, pooled, age, stale, w


def lognormal_median(mean, sigma):
    return mean * math.exp(-sigma ** 2 / 2)


def refusals(policy_fn, always, age, stale, w, median, sigma, rng):
    k = rng.choice(age.size, SAMPLES, p=w)
    v = rng.lognormal(math.log(median), sigma, SAMPLES)
    a, st = age[k], stale[k]
    if always:
        refused = st
    else:
        max_age = np.array([policy_fn(x) for x in v])
        refused = st | (a > max_age)
    return 1000.0 * float(refused.mean())


def pareto3(rows):
    keys = ("fetches_per_1000", "expected_loss_per_1000_brl", "refused_per_1000")
    out = []
    for i, a in enumerate(rows):
        dominated = any(all(b[k] <= a[k] for k in keys) and any(b[k] < a[k] for k in keys) for j, b in enumerate(rows) if j != i)
        if not dominated:
            out.append(i)
    return out


def main():
    inputs = provenance.stamp()
    av, pix, m = load_json("availability.json"), load_json("pix.json"), load_json("measured.json")
    per, pooled, age, stale, w = availability(av)
    lam = M.lambda_per_hour(m)["per_hour"]
    sigma = S.PARAMS["value_sigma"]
    scales = {"Pix B2B (titulares diferentes)": V.median("B2B", sigma),  # the main scenario (value_scale.py)
              "Cartão de crédito empresarial": V.median("CARD", sigma)}
    rates = {"Pix B2B (titulares diferentes)": V.rate("B2B"), "Cartão de crédito empresarial": V.rate("CARD")}

    # delay pool and base parameters exactly as in simulate_measured.py (measured cadence)
    rng = np.random.default_rng(SEED)
    staff = M.staffing(M.load()[1])
    p, wt = M.cadence_mix(m, False)
    comp = rng.uniform(0, M.WEEK, M.POOL)
    pool, _ = M.exposure(rng, comp, staff, p, wt)
    base = {**S.PARAMS, "lambda_per_hour": lam, "delay_pool": pool,
            "publication_delay": {"crl_interval_h": 0.0, "publish_latency_h": 0.0}}

    out = {"seed": SEED, "window": {"from": min(x["versions"][0]["uploaded"] for x in av["sources"].values()),
                                    "to": av["summary_generated_at"]},
           "availability": {"per_source": per, "pooled": pooled},
           "value_scales_median_brl": scales, "scenarios": {}}
    for name, median in scales.items():
        prm = {**base, "value_median_brl": median, "actions_per_hour": rates[name], "credentials": V.credentials_for(rates[name])}
        rows = []
        for pol, sweep in S.build_policies(lam).items():
            for label, fn in sweep:
                r = S.simulate(fn, prm["seed"], lam, prm)
                rows.append({"policy": pol, "setting": label,
                             "fetches_per_1000": round(r["fetches_per_1000"], 2),
                             "expected_loss_per_1000_brl": round(r["expected_loss_per_1000_brl"], 6),
                             "refused_per_1000": round(refusals(fn, pol == "consultar sempre", age, stale, w, median, sigma, rng), 2)})
        front = [rows[i] for i in sorted(pareto3(rows), key=lambda i: rows[i]["fetches_per_1000"])]
        out["scenarios"][name] = {"value_median_brl": median, "rows": rows, "pareto3": front}
        print(name, "median", median)
        for r in rows:
            print(f"  {r['policy']:22} {r['setting']:18} fetches={r['fetches_per_1000']:8.1f} loss={r['expected_loss_per_1000_brl']:10.4f} refused={r['refused_per_1000']:7.1f}")
    out["inputs"] = inputs
    with open(os.path.join(HERE, "results_availability.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps(out["availability"], ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
