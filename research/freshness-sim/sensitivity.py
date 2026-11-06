"""
Sensitivity of the policy comparison to the two parameters the measurement cannot pin down: the rate at which a
certificate stops being trustworthy (lambda) and the value of the actions.

The measured lambda is a floor (results_measured.json: 11 end-user CRLs; expired certificates leave the CRL) and
counts every revocation, not only compromises, so the comparison is repeated from 1x to 100x the measured rate,
for the two Pix scales of value_scale.py (B2B, the main one, and P2B). The publication delay is the measured one
(simulate_measured.py, reissue every 0.5 h).

For each scenario: the gain of the proportional policy over a fixed deadline that makes the same number of status
fetches (fixed-deadline loss interpolated on log(fetches)), as R$ per 1,000 actions and as a share of the loss a
verifier can avoid at all (loss minus the always-fetch floor, which comes from the AC's own delay).

    python3 -I sensitivity.py   # numpy only; writes sensitivity.json (about 10 minutes on 4 cores)
"""
import json
import math
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script directory out of sys.path
import simulate as S  # noqa: E402
import simulate_measured as M  # noqa: E402

MULTIPLIERS = (1, 3, 10, 30, 100)
import value_scale as V  # noqa: E402
from multiprocessing import Pool  # noqa: E402

SCALES = {"Pix B2B": V.median("B2B"), "Pix P2B": V.median("P2B")}
MEDIANS_BRL = tuple(SCALES.values())


def interp_fixed(fixed, fetches):
    """Loss of the fixed-deadline policy at `fetches`, linear in log(fetches) between its sweep points."""
    pts = sorted((p["fetches_per_1000"], p["expected_loss_per_1000_brl"]) for p in fixed)
    xs = [math.log(x) for x, _ in pts]
    x = math.log(fetches)
    if x <= xs[0] or x >= xs[-1]:
        return None
    return float(np.interp(x, xs, [y for _, y in pts]))


def measured_delay_pool():
    """Exposure delays with the measured cadence (reissue every 0.5 h), as in simulate_measured.py."""
    m, w = M.load()
    rng = np.random.default_rng(M.SEED)
    p, wt = M.cadence_mix(m, False)
    pool, _ = M.exposure(rng, rng.uniform(0, M.WEEK, M.POOL), w / w.max(), p, wt)
    return M.lambda_per_hour(m)["per_hour"], pool


def gain_over_fixed(row, fixed, floor):
    """Gain of one proportional point over the fixed deadline with the same fetches, or None outside its range."""
    ref = interp_fixed(fixed, row["fetches_per_1000"])
    if ref is None:
        return None
    gain = ref - row["expected_loss_per_1000_brl"]
    return {"setting": row["setting"], "fetches_per_1000": row["fetches_per_1000"], "loss": row["expected_loss_per_1000_brl"],
            "fixed_loss_same_fetches": round(ref, 4), "gain_brl_per_1000": round(gain, 4),
            "share_of_avoidable": round(gain / (ref - floor) if ref > floor else 0.0, 4)}


def best_gain(rows):
    """(always-fetch floor, best proportional point by share of the avoidable loss removed)."""
    floor = next(r for r in rows if r["policy"] == "consultar sempre")["expected_loss_per_1000_brl"]
    fixed = [r for r in rows if r["policy"] == "prazo fixo"]
    gains = [g for r in rows if r["policy"] == "proporcional ao valor" for g in [gain_over_fixed(r, fixed, floor)] if g]
    return floor, max(gains, key=lambda g: g["share_of_avoidable"], default=None)


def run(task):
    med, k, lam, pool = task
    base = {**S.PARAMS, "publication_delay": {"crl_interval_h": 0.0, "publish_latency_h": 0.0}, "delay_pool": pool,
            "value_sigma": V.SIGMA}
    rows = M.sweep({**base, "lambda_per_hour": lam * k, "value_median_brl": med}, lam * k)["rows"]
    floor, best = best_gain(rows)
    return {"multiplier": k, "median_brl": med, "lambda_per_hour": lam * k, "floor_brl_per_1000": floor, "best": best, "rows": rows}


def main():
    lam, pool = measured_delay_pool()
    out = {"seed": M.SEED, "lambda_measured_per_hour": lam, "multipliers": MULTIPLIERS, "medians_brl": MEDIANS_BRL,
           "scales": SCALES, "sigma": V.SIGMA, "scenarios": []}
    tasks = [(med, k, lam, pool) for med in MEDIANS_BRL for k in MULTIPLIERS]
    with Pool() as p:
        for row in p.imap(run, tasks):
            out["scenarios"].append(row)
            print(json.dumps({kk: vv for kk, vv in row.items() if kk != "rows"}, ensure_ascii=False), flush=True)
    with open(os.path.join(HERE, "sensitivity.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
