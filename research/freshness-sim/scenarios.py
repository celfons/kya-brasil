"""
Robustness of the policy comparison to the parameters that are not measured: the shape of the value distribution
(sigma) and the traffic (actions per hour per credential). Two base scenarios, Pix and company credit card, each with
the value and the rate of its own source (value_scale.py); then sigma and an agent more active than people (10 and
100 times the observed rate). Each run also reports the loss on the top 1% of actions
by value (tail_loss_per_1000_tail_actions_brl), where the proportional policy asks for the freshest evidence.

Every scenario uses the measured rate and the measured cadence (simulate_measured.py, reissue every 0.5 h). When the
traffic changes, the number of credentials changes inversely, so every run simulates about the same number of actions.

    python3 -I scenarios.py   # numpy only; writes scenarios.json (a few minutes on 4 cores, the 20/h run is the longest)
"""
import json
import math
import os
import sys
from multiprocessing import Pool

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script directory out of sys.path
import simulate as S  # noqa: E402
import simulate_measured as M  # noqa: E402
import value_scale as V  # noqa: E402
from sensitivity import measured_delay_pool  # noqa: E402

LOW = V.sigma_lower_bound()
Z99 = 2.326348  # the top 1% of the log-normal: median * exp(sigma * z_0.99)
PIX, CARD = V.rate("B2B"), V.rate("CARD")
SCENARIOS = [  # (name, kind, scale, sigma, actions per hour)
    ("principal", "base", "B2B", V.SIGMA, PIX),
    ("cartão", "base", "CARD", V.SIGMA, CARD),
    ("sigma no limite inferior", "sigma", "B2B", LOW, PIX),
    ("sigma 2,0", "sigma", "B2B", 2.0, PIX),
    ("Pix, 10 vezes o ritmo", "ritmo", "B2B", V.SIGMA, 10 * PIX),
    ("Pix, 100 vezes o ritmo", "ritmo", "B2B", V.SIGMA, 100 * PIX),
    ("cartão, 100 vezes o ritmo", "ritmo", "CARD", V.SIGMA, 100 * CARD),
]


def pick(rows, policy, setting):
    return next(r for r in rows if r["policy"] == policy and r["setting"] == setting)


def run(task):
    name, kind, scale, sigma, rate, lam, pool = task
    med = V.median(scale, sigma) if scale else 200.0
    creds = V.credentials_for(rate)
    prm = {**S.PARAMS, "publication_delay": {"crl_interval_h": 0.0, "publish_latency_h": 0.0}, "delay_pool": pool,
           "lambda_per_hour": lam, "value_median_brl": med, "value_sigma": sigma, "actions_per_hour": rate,
           "credentials": creds, "tail_threshold_brl": med * math.exp(sigma * Z99)}
    sw = M.sweep(prm, lam)
    rows, front = sw["rows"], sw["pareto"]
    prop, fixed = pick(rows, "proporcional ao valor", "L=0.01"), pick(rows, "prazo fixo", "12 h")
    lf = S.fraud_ruler_L()
    prop_fraude = pick(rows, "proporcional ao valor", f"L={lf:g}")
    return {"name": name, "kind": kind, "scale": scale, "median_brl": med, "sigma": sigma, "actions_per_hour": rate,
            "credentials": creds, "floor_brl_per_1000": pick(rows, "consultar sempre", "0 h")["expected_loss_per_1000_brl"],
            "proportional_L001": prop, "L_fraude": lf, "proportional_Lfraude": prop_fraude, "fixed_12h": fixed,
            "proportional_on_front": sum(1 for r in front if r["policy"] == "proporcional ao valor"), "rows": rows}


def main():
    lam, pool = measured_delay_pool()
    tasks = [(*s, lam, pool) for s in SCENARIOS]
    out = {"seed": S.PARAMS["seed"], "lambda_per_hour": lam, "sigma_lower_bound": LOW, "means_brl": V.means(), "scenarios": []}
    with Pool() as p:
        for r in p.imap(run, tasks):
            out["scenarios"].append(r)
            print(json.dumps({k: v for k, v in r.items() if k != "rows"}, ensure_ascii=False), flush=True)
    with open(os.path.join(HERE, "scenarios.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
