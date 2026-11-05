"""
Sensitivity of the policy comparison to the two parameters the measurement cannot pin down: the rate at which a
certificate stops being trustworthy (lambda) and the value of the actions.

The measured lambda is a floor (results_measured.json: 11 end-user CRLs; expired certificates leave the CRL) and
counts every revocation, not only compromises, so the comparison is repeated from 1x to 100x the measured rate,
for a median action of R$ 200 (simulate.py) and R$ 2,000. The publication delay is the measured one
(simulate_measured.py, reissue every 0.5 h).

For each scenario: the gain of the proportional policy over a fixed deadline that makes the same number of status
fetches (fixed-deadline loss interpolated on log(fetches)), as R$ per 1,000 actions and as a share of the loss a
verifier can avoid at all (loss minus the always-fetch floor, which comes from the AC's own delay).

    python3 -I sensitivity.py   # numpy only; writes sensitivity.json (about 20 minutes)
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
MEDIANS_BRL = (200.0, 2000.0)


def interp_fixed(fixed, fetches):
    """Loss of the fixed-deadline policy at `fetches`, linear in log(fetches) between its sweep points."""
    pts = sorted((p["fetches_per_1000"], p["expected_loss_per_1000_brl"]) for p in fixed)
    xs = [math.log(x) for x, _ in pts]
    x = math.log(fetches)
    if x <= xs[0] or x >= xs[-1]:
        return None
    return float(np.interp(x, xs, [y for _, y in pts]))


def main():
    m, w = M.load()
    staff = w / w.max()
    lam = M.lambda_per_hour(m)["per_hour"]
    rng = np.random.default_rng(M.SEED)
    p, wt = M.cadence_mix(m, False)
    pool, _ = M.exposure(rng, rng.uniform(0, M.WEEK, M.POOL), staff, p, wt)
    base = {**S.PARAMS, "publication_delay": {"crl_interval_h": 0.0, "publish_latency_h": 0.0}, "delay_pool": pool}
    out = {"seed": M.SEED, "lambda_measured_per_hour": lam, "multipliers": MULTIPLIERS, "medians_brl": MEDIANS_BRL, "scenarios": []}
    for med in MEDIANS_BRL:
        for k in MULTIPLIERS:
            prm = {**base, "lambda_per_hour": lam * k, "value_median_brl": med}
            res = M.sweep(prm, lam * k)["rows"]
            floor = next(r for r in res if r["policy"] == "consultar sempre")["expected_loss_per_1000_brl"]
            fixed = [r for r in res if r["policy"] == "prazo fixo"]
            best = None
            for r in res:
                if r["policy"] != "proporcional ao valor":
                    continue
                ref = interp_fixed(fixed, r["fetches_per_1000"])
                if ref is None:
                    continue
                gain = ref - r["expected_loss_per_1000_brl"]
                share = gain / (ref - floor) if ref > floor else 0.0
                if best is None or share > best["share_of_avoidable"]:
                    best = {"setting": r["setting"], "fetches_per_1000": r["fetches_per_1000"], "loss": r["expected_loss_per_1000_brl"],
                            "fixed_loss_same_fetches": round(ref, 4), "gain_brl_per_1000": round(gain, 4), "share_of_avoidable": round(share, 4)}
            row = {"multiplier": k, "median_brl": med, "lambda_per_hour": lam * k, "floor_brl_per_1000": floor, "best": best, "rows": res}
            out["scenarios"].append(row)
            print(json.dumps({kk: vv for kk, vv in row.items() if kk != "rows"}, ensure_ascii=False), flush=True)
    with open(os.path.join(HERE, "sensitivity.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
