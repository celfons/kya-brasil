"""
EXPLORATORY: the exposure window with the publication delay MEASURED by the collector, instead of the model's
"next CRL (phase uniform over the reissue interval) + dissemination U(0, 4) h" (the DOC-ICP-05 4.9.8 maximum).

    python3 -I simulate_measured_delay.py   # numpy only; reads data/delays.json, data/availability.json and the
                                           # inputs of simulate_measured.py; writes results_measured_delay.json

Model, as simulate_measured.py except for the publication:
  - compromise uniform over the week; the AC registers the revocation in the first staffed hour slot (unchanged);
  - wait for a CRL that lists it: drawn from the delays the collector measured (data/delays.json: thisUpdate of the
    first collected CRL containing the revocation minus its revocationDate), each source weighing by its entries;
  - dissemination: drawn from uploaded minus thisUpdate of every CRL version the collector stored
    (data/availability.json), an UPPER bound, since the collector polls hourly. A lower-bound variant sets it to 0.
The figures of simulate_measured.py, which the paper cites, are not changed; they are repeated here for comparison.
"""
import json
import os
import sys
from datetime import datetime

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script directory out of sys.path
import simulate as S  # noqa: E402
import simulate_measured as M  # noqa: E402

DATA = os.path.join(HERE, "data")
SEED = 20261107
PER_SLOT = 4000


def load_json(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return json.load(f)


def hours(a, b):
    return (datetime.fromisoformat(b.replace("Z", "+00:00")) - datetime.fromisoformat(a.replace("Z", "+00:00"))).total_seconds() / 3600


def weighted_pool(per_source):
    """(values, probabilities): every observation of a source shares that source's weight (its entries)."""
    vals, wts = [], []
    for entries, xs in per_source:
        if not xs:
            continue
        vals.extend(xs)
        wts.extend([entries / len(xs)] * len(xs))
    w = np.array(wts, float)
    return np.array(vals, float), w / w.sum()


def pools():
    d, av = load_json("delays.json"), load_json("availability.json")
    delay = weighted_pool([(s["entries"], s["delays_h"]) for s in d["sources"].values()])
    diss = weighted_pool([(s["entries"], [max(0.0, hours(v["this_update"], v["uploaded"])) for v in s["versions"]])
                          for s in av["sources"].values()])
    return delay, diss


def describe(x):
    return {"n": int(x.size), "mean_h": round(float(x.mean()), 3), "p50_h": round(float(np.median(x)), 3),
            "p95_h": round(float(np.quantile(x, 0.95)), 3), "max_h": round(float(x.max()), 3)}


def exposure(rng, comp, staff, delay, diss):
    rev = M.revocation_time(rng, comp, staff)
    pub = rng.choice(delay[0], comp.size, p=delay[1])
    dis = rng.choice(diss[0], comp.size, p=diss[1]) if diss is not None else 0.0
    return rev - comp + pub + dis


def window(rng, staff, delay, diss):
    rows, allv = [], []
    for s in range(M.WEEK):
        e = exposure(rng, s + rng.random(PER_SLOT), staff, delay, diss)
        rows.append(float(e.mean()))
        allv.append(e)
    allv = np.concatenate(allv)
    mean = np.array(rows)
    biz = np.array([(s // 24) < 5 and 8 <= s % 24 < 18 for s in range(M.WEEK)])
    r = lambda x: round(float(x), 2)
    return {"mean_h": r(allv.mean()), "p50_h": r(np.median(allv)), "p95_h": r(np.quantile(allv, 0.95)),
            "friday_19h_mean_h": r(mean[4 * 24 + 19]), "business_hours_mean_h": r(mean[biz].mean()),
            "off_hours_mean_h": r(mean[~biz].mean()), "weekend_mean_h": r(mean[120:].mean())}


def main():
    m, w = M.load()
    staff = w / w.max()
    lam = M.lambda_per_hour(m)["per_hour"]
    delay, diss = pools()
    rng = np.random.default_rng(SEED)
    out = {"seed": SEED, "measured": {"delay_to_crl": describe(delay[0]), "dissemination_upper_bound": describe(diss[0])},
           "window": {}, "sweep": {}}
    with open(os.path.join(HERE, "results_measured.json"), encoding="utf-8") as f:
        ref = json.load(f)["counterfactual"]["medido (reemissão 0,5 h)"]
    out["window"]["modelo do artigo (próxima LCR + divulgação U(0, 4) h)"] = {
        k: ref[k] for k in ("mean_h", "p50_h", "p95_h", "business_hours_mean_h", "off_hours_mean_h", "weekend_mean_h")}
    out["window"]["modelo do artigo (próxima LCR + divulgação U(0, 4) h)"]["friday_19h_mean_h"] = ref["friday_19h"]["mean_h"]
    out["window"]["atraso medido + divulgação medida (limite superior)"] = window(rng, staff, delay, diss)
    out["window"]["atraso medido, sem divulgação (limite inferior)"] = window(rng, staff, delay, None)

    base = {**S.PARAMS, "lambda_per_hour": lam, "publication_delay": {"crl_interval_h": 0.0, "publish_latency_h": 0.0}}
    pool = exposure(rng, rng.uniform(0, M.WEEK, M.POOL), staff, delay, diss)
    out["sweep"]["atraso medido + divulgação medida"] = M.sweep({**base, "delay_pool": pool}, lam)
    with open(os.path.join(HERE, "results_measured_delay.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in out.items() if k != "sweep"}, ensure_ascii=False, indent=1))
    for r in out["sweep"]["atraso medido + divulgação medida"]["pareto"]:
        print(f"  pareto: {r['policy']:22} {r['setting']:10} {r['fetches_per_1000']:8.1f} {r['expected_loss_per_1000_brl']:.4f}")


if __name__ == "__main__":
    main()
