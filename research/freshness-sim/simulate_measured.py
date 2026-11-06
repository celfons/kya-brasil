"""
Freshness policies with MEASURED parameters, and the weekend exposure window.

Inputs come from data/ (written by fetch_measured.py from the public ICP-Brasil CRL collector), so the run is
offline and reproducible:

    python3 -I simulate_measured.py   # numpy only; writes results_measured.json

Measured model (certificate evidence):
  - lambda: end-user revocations per month in 2026 (Jan-Oct, the 11 collected end-user CRLs) x 12 / active
    ICP-Brasil certificates (ITI). A FLOOR: the collector covers a few of the end-user ACs, and a CRL drops a
    certificate once it expires, so past months undercount;
  - the moment a credential stops being trustworthy (compromise) is uniform over the week; the AC acts on it
    only in an hour slot it is staffed, with probability w(h) / max(w) per hour-of-week slot h, where w is the
    empirical weekday x hour distribution of revocation dates (data/weekday_hour.csv); the first staffed slot
    at or after the compromise is the revocation, uniform inside the slot;
  - the revocation enters the next CRL of its AC (publication interval P, phase uniform) and the CRL reaches
    the distribution point within U(0, 4) h (DOC-ICP-05 4.9.8 maximum);
  - P per AC from the collector: observed reissue every 0.5 h where two versions were seen; nextUpdate minus
    thisUpdate (1 h or 6 h) as the conservative bound. Each AC weighs by its 2026 revocations share proxy
    (entries of the CRLs still in force).
The policy sweep and the loss formula are those of simulate.py; the value of the actions has the Pix B2B scale
(value_scale.py).
"""
import csv
import json
import math
import os

import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script directory out of sys.path
import simulate as S  # noqa: E402
import value_scale as V  # noqa: E402
DATA = os.path.join(HERE, "data")
SEED = 20261105
DISSEMINATION_H = 4.0
POOL = 200_000
WEEK = 168


def load():
    with open(os.path.join(DATA, "measured.json"), encoding="utf-8") as f:
        m = json.load(f)
    w = np.zeros(WEEK)
    with open(os.path.join(DATA, "weekday_hour.csv"), encoding="utf-8") as f:
        for r in csv.DictReader(f):
            w[int(r["weekday"]) * 24 + int(r["hour_brt"])] = int(r["revocations"])
    return m, w


def lambda_per_hour(m):
    months = {k: v for k, v in m["monthly_2026_usuario_final"].items() if "2026-01" <= k <= "2026-10"}
    per_month = sum(months.values()) / len(months)
    active = int(m["iti"]["ativos"])
    per_year = per_month * 12 / active
    return {"months": months, "per_month_mean": per_month, "active": active, "per_year": per_year,
            "per_hour": per_year / 8760.0}


def cadence_mix(m, conservative):
    """(intervals, weights) over the end-user CRLs still issued in 2026."""
    p, wt = [], []
    for c in m["cadence_usuario_final"].values():
        if not c["last_this_update"].startswith("2026") or c["entries"] == 0:
            continue
        p.append(c["validity_h"] if conservative or c["reissue_h"] is None else c["reissue_h"])
        wt.append(c["entries"])
    wt = np.array(wt, float)
    return np.array(p), wt / wt.sum()


def revocation_time(rng, comp, staff):
    """First staffed hour slot at or after comp (hours from Monday 00:00 BRT); uniform inside the slot."""
    out = np.full(comp.shape, np.nan)
    start = comp.copy()
    slot = np.floor(comp).astype(np.int64)
    pending = np.ones(comp.shape, bool)
    while pending.any():
        i = np.flatnonzero(pending)
        hit = rng.random(i.size) < staff[slot[i] % WEEK]
        j = i[hit]
        out[j] = rng.uniform(start[j], slot[j] + 1.0)
        slot[i[~hit]] += 1
        start[i[~hit]] = slot[i[~hit]]
        pending[j] = False
    return out


def exposure(rng, comp, staff, intervals, weights, dissemination=True):
    rev = revocation_time(rng, comp, staff)
    p = rng.choice(intervals, comp.size, p=weights)
    pub = rng.uniform(0, 1, comp.size) * p
    dis = rng.uniform(0, DISSEMINATION_H, comp.size) if dissemination else 0.0
    return rev - comp + pub + dis, rev - comp


def counterfactual(rng, staff, intervals, weights, per_slot=4000):
    """Hours from compromise to the revocation being in a disseminated CRL, per hour-of-week of compromise."""
    rows, allv = [], []
    for s in range(WEEK):
        comp = s + rng.random(per_slot)
        e, r = exposure(rng, comp, staff, intervals, weights)
        rows.append({"weekday": s // 24, "hour_brt": s % 24, "mean_h": float(e.mean()),
                     "p95_h": float(np.quantile(e, 0.95)), "mean_to_revocation_h": float(r.mean())})
        allv.append(e)
    allv = np.concatenate(allv)
    mean = np.array([r["mean_h"] for r in rows])
    wkday = mean[: 5 * 24].mean()
    wkend = mean[5 * 24:].mean()
    biz = np.array([(s // 24) < 5 and 8 <= s % 24 < 18 for s in range(WEEK)])
    worst = int(np.argmax(mean))
    fri19 = 4 * 24 + 19
    rnd = lambda x: round(float(x), 2)
    return {
        "mean_h": rnd(allv.mean()), "p50_h": rnd(np.quantile(allv, 0.5)), "p95_h": rnd(np.quantile(allv, 0.95)),
        "max_sampled_h": rnd(allv.max()),
        "worst_slot": {"weekday": S_DAYS[worst // 24], "hour_brt": worst % 24, "mean_h": rnd(mean[worst]),
                       "p95_h": rnd(rows[worst]["p95_h"])},
        "friday_19h": {"mean_h": rnd(mean[fri19]), "p95_h": rnd(rows[fri19]["p95_h"])},
        "business_hours_mean_h": rnd(mean[biz].mean()), "off_hours_mean_h": rnd(mean[~biz].mean()),
        "weekday_mean_h": rnd(wkday), "weekend_mean_h": rnd(wkend), "weekend_over_weekday": rnd(wkend / wkday),
        "per_slot": [{k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()} for r in rows],
    }


S_DAYS = ["seg", "ter", "qua", "qui", "sex", "sab", "dom"]


def sweep(prm, lam_assumed):
    flat = []
    for name, sw in S.build_policies(lam_assumed).items():
        for label, fn in sw:
            r = S.simulate(fn, prm["seed"], prm["lambda_per_hour"], prm)
            row = {"policy": name, "setting": label, "fetches_per_1000": round(r["fetches_per_1000"], 2),
                   "expected_loss_per_1000_brl": round(r["expected_loss_per_1000_brl"], 6)}
            if prm.get("tail_threshold_brl") is not None:
                row["tail_loss_per_1000_tail_actions_brl"] = round(r["tail_loss_per_1000_tail_actions_brl"], 4)
                row["tail_share_of_loss"] = round(r["tail_share_of_loss"], 4)
            flat.append(row)
    front = [flat[i] for i in sorted(S.pareto(flat), key=lambda i: flat[i]["fetches_per_1000"])]
    return {"rows": flat, "pareto": front}


def main():
    m, w = load()
    staff = w / w.max()
    lam = lambda_per_hour(m)
    rng = np.random.default_rng(SEED)
    biz = np.array([(s // 24) < 5 and 8 <= s % 24 < 18 for s in range(WEEK)])
    out = {
        "seed": SEED,
        "value_scale": {"source": "Pix B2B (value_scale.py)", "mean_brl": V.means()["B2B"], "median_brl": V.median("B2B"), "sigma": V.SIGMA,
                        "actions_per_hour": V.rate("B2B")},
        "lambda": {**lam, "note": "floor: 11 end-user CRLs only; expired certificates leave the CRL"},
        "weekday_hour": {"total": int(w.sum()), "business_share": round(float(w[biz].sum() / w.sum()), 4),
                         "weekend_share": round(float(w[120:].sum() / w.sum()), 4),
                         "business_hours_share_of_week": round(biz.mean(), 4)},
        "counterfactual": {}, "pools": {}, "scenarios": {},
    }
    pools = {}
    for label, conservative in (("medido (reemissão 0,5 h)", False), ("conservador (nextUpdate 1 h/6 h)", True)):
        p, wt = cadence_mix(m, conservative)
        out["counterfactual"][label] = counterfactual(rng, staff, p, wt)
        comp = rng.uniform(0, WEEK, POOL)
        e, _ = exposure(rng, comp, staff, p, wt)
        pools[label] = e
        out["pools"][label] = {"intervals_h": p.tolist(), "weights": [round(x, 4) for x in wt],
                               "mean_h": round(float(e.mean()), 2), "p95_h": round(float(np.quantile(e, 0.95)), 2)}

    base = {**S.PARAMS, "value_median_brl": V.median("B2B"), "value_sigma": V.SIGMA,  # Pix scenario (value_scale.py)
            "actions_per_hour": V.rate("B2B"), "credentials": V.credentials_for(V.rate("B2B"))}
    base.pop("publication_delay")
    base["publication_delay"] = {"crl_interval_h": 0.0, "publish_latency_h": 0.0}  # unused with delay_pool
    lam_m = lam["per_hour"]
    scen = {
        "medido": ({**base, "lambda_per_hour": lam_m, "delay_pool": pools["medido (reemissão 0,5 h)"]}, lam_m),
        "medido, cadência conservadora": ({**base, "lambda_per_hour": lam_m, "delay_pool": pools["conservador (nextUpdate 1 h/6 h)"]}, lam_m),
        "atraso medido, λ sintético 1e-5": ({**base, "lambda_per_hour": 1e-5, "delay_pool": pools["medido (reemissão 0,5 h)"]}, 1e-5),
    }
    for name, (prm, la) in scen.items():
        out["scenarios"][name] = {"lambda_per_hour": la, **sweep(prm, la)}
    with open(os.path.join(HERE, "results.json"), encoding="utf-8") as f:
        old = json.load(f)
    out["scenarios"]["sintético (results.json)"] = {"lambda_per_hour": old["params"]["lambda_per_hour"], "pareto": old["pareto"]}

    with open(os.path.join(HERE, "results_measured.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    summary = {k: v for k, v in out.items() if k in ("lambda", "weekday_hour", "pools")}
    summary["counterfactual"] = {k: {kk: vv for kk, vv in v.items() if kk != "per_slot"} for k, v in out["counterfactual"].items()}
    print(json.dumps(summary, ensure_ascii=False, indent=1, default=float))


if __name__ == "__main__":
    main()
