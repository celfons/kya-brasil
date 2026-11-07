"""
Freshness policies for offline verification of agent credentials: a Monte Carlo comparison.

Question: when a verifier accepts an agent's action using status evidence of some age (an issuer-signed
status, or an ICP-Brasil CRL), how much expected loss does each freshness policy leave, and how many status
fetches does it cost? The policies on the Pareto front (no other policy has both less loss and fewer fetches)
are the viable ones.

Everything here is a MODEL with HYPOTHETICAL parameters, stated in PARAMS. The research replaces the rate of
revocation and the publication delay with values measured from the ICP-Brasil CRLs. Run:

    python3 -I simulate.py            # writes results.json next to this file

Model, per credential, over a horizon of H hours:
  - actions arrive as a Poisson process of rate r per hour; values are log-normal (heavy-tailed: a few large
    actions carry most of the value, the 80/20 shape);
  - the credential stops being in force at a random time R ~ Exp(lambda); the revocation becomes visible to
    a status fetch only after a publication delay d (ICP-Brasil, DOC-ICP-05 v7.0: a CRL at most every 6 h,
    published at most 4 h after generation, so d ~ U(0, 6) + U(0, 4) hours in the worst case allowed);
  - the verifier caches the last evidence; a policy says, for an action of value v, how old that evidence may
    be; when it is older, the verifier fetches fresh evidence (cost 1) before deciding;
  - an action accepted at time t on evidence fetched at t_f is a loss of v when R < t and the revocation was
    not yet visible at t_f, i.e. t_f - d < R < t. Its probability is computed in closed form over R, and
    averaged over sampled d, so rare revocations do not need millions of runs.

The same comparison is repeated for credential evidence, which the issuer updates at once (no publication
delay). A further scenario models a stolen agent key: the attacker sends actions just under the mandate's
per-operation ceiling until the revocation becomes visible, and the mandate's daily ceiling may stop it.
"""
import json
import math
import os

import numpy as np

PARAMS = {
    "seed": 20261104,
    "credentials": 400,            # simulated credentials (agents)
    "horizon_hours": 24 * 30,      # 30 days each
    "actions_per_hour": 2.0,       # per credential
    "value_median_brl": 200.0,     # log-normal median
    "value_sigma": 1.6,            # log-normal shape: about 80% of the value in the top 20% of actions
    "lambda_per_hour": 1e-5,       # HYPOTHETICAL rate at which a credential stops being in force (~8.4%/year)
    "publication_delay": {"crl_interval_h": 6.0, "publish_latency_h": 4.0},  # DOC-ICP-05 v7.0 maxima
    "delay_samples": 64,
}

POLICIES = {
    # name: list of (label, max_age_fn(value) -> hours); one entry per point of the sweep
}


def fixed(hours):
    return lambda v: hours


def proportional(loss_brl, lam, cap_h):
    return lambda v: min(cap_h, loss_brl / (v * lam)) if v > 0 else cap_h


def tiers(cuts):
    # cuts: list of (upper_value_brl, max_age_h), ascending; the last upper bound is infinity
    def f(v):
        for upper, age in cuts:
            if v < upper:
                return age
        return cuts[-1][1]
    return f


def fraud_ruler_L():
    """L (BRL per action) from the Pix fraud ruler: the share of value that Pix loses to accepted fraud
    (data/pix_fraud.json, Banco Central open data) applied to the mean value of a Pix payment between companies
    (value_scale.py). The paper's main setting of the proportional policy. None when the data are not fetched."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "pix_fraud.json"), encoding="utf-8") as f:
            share = json.load(f)["total"]["fraud_share_of_value"]
    except FileNotFoundError:
        return None
    import value_scale as V
    return round(share * V.means()["B2B"], 2)


def build_policies(lam):
    p = {}
    p["consultar sempre"] = [("0 h", fixed(0.0))]
    p["prazo fixo"] = [(f"{h:g} h", fixed(h)) for h in (0.25, 0.5, 1, 2, 4, 6, 12, 24, 48)]
    Ls = [0.01, 0.03, 0.1, 0.3, 1, 3, 10]
    lf = fraud_ruler_L()
    if lf is not None and lf not in Ls:
        Ls = sorted(Ls + [lf])
    p["proporcional ao valor"] = [(f"L={L:g}", proportional(L, lam, 24.0)) for L in Ls]
    p["faixas de valor"] = [
        ("3 faixas, folgada", tiers([(100, 24), (10_000, 6), (math.inf, 1)])),
        ("3 faixas, média", tiers([(100, 12), (10_000, 1), (math.inf, 0.25)])),
        ("3 faixas, rígida", tiers([(100, 6), (10_000, 0.5), (math.inf, 0)])),
    ]
    return p


def simulate(policy_fn, rng_seed, lam, prm):
    rng = np.random.default_rng(rng_seed)
    H = prm["horizon_hours"]
    n_cred = prm["credentials"]
    ci = prm["publication_delay"]["crl_interval_h"]
    pl = prm["publication_delay"]["publish_latency_h"]
    mu = math.log(prm["value_median_brl"])
    sigma = prm["value_sigma"]
    fetches = 0
    actions = 0
    loss = 0.0
    value_total = 0.0
    values_all = []
    fetch_values = []
    tail = prm.get("tail_threshold_brl")  # optional: loss on the actions at or above this value
    tail_loss = 0.0
    tail_n = 0
    for _ in range(n_cred):
        n = rng.poisson(prm["actions_per_hour"] * H)
        times = np.sort(rng.uniform(0, H, n))
        values = rng.lognormal(mu, sigma, n)
        d = rng.uniform(0, ci, prm["delay_samples"]) + rng.uniform(0, pl, prm["delay_samples"])
        if prm.get("no_publication_delay"):
            d = np.zeros(prm["delay_samples"])
        if prm.get("delay_pool") is not None:  # measured delays (simulate_measured.py)
            d = rng.choice(prm["delay_pool"], prm["delay_samples"])
        t_f = -math.inf  # no evidence yet: the first action always fetches
        for t, v in zip(times, values):
            max_age = policy_fn(v)
            if t - t_f > max_age:
                t_f = t
                fetches += 1
                fetch_values.append(v)
            # P(t_f - d < R < t), R ~ Exp(lam), averaged over d
            lo = np.maximum(0.0, t_f - d)
            p = float(np.mean(np.exp(-lam * lo) - math.exp(-lam * t)))
            loss += v * max(0.0, p)
            if tail is not None and v >= tail:
                tail_loss += v * max(0.0, p)
                tail_n += 1
            actions += 1
            value_total += v
            values_all.append(v)
    return {
        "actions": actions,
        "fetches": fetches,
        "fetches_per_1000": 1000.0 * fetches / actions,
        "expected_loss_per_1000_brl": 1000.0 * loss / actions,
        "expected_loss_share_of_value": loss / value_total,
        "values": np.array(values_all),
        "fetch_values": np.array(fetch_values),
        "tail_actions": tail_n,
        "tail_loss_per_1000_tail_actions_brl": 1000.0 * tail_loss / tail_n if tail_n else None,
        "tail_share_of_loss": tail_loss / loss if tail is not None and loss else None,
    }


def pareto(points):
    """Indices of points not dominated (lower loss and fewer fetches is better)."""
    keep = []
    for i, a in enumerate(points):
        dominated = any(
            (b["fetches_per_1000"] <= a["fetches_per_1000"] and b["expected_loss_per_1000_brl"] <= a["expected_loss_per_1000_brl"])
            and (b["fetches_per_1000"] < a["fetches_per_1000"] or b["expected_loss_per_1000_brl"] < a["expected_loss_per_1000_brl"])
            for j, b in enumerate(points) if j != i
        )
        if not dominated:
            keep.append(i)
    return keep


def top_share(values, top=0.2):
    v = np.sort(values)[::-1]
    k = max(1, int(len(v) * top))
    return float(v[:k].sum() / v.sum())


def stolen_key(prm, policy_fn, per_op_ceiling, daily_ceiling, detection_h, attack_rate_per_h, rng_seed):
    """Expected loss when an attacker with the agent key sends actions just under the per-operation ceiling
    from compromise until the revocation is visible to the verifier's cached evidence."""
    rng = np.random.default_rng(rng_seed)
    ci = prm["publication_delay"]["crl_interval_h"]
    pl = prm["publication_delay"]["publish_latency_h"]
    runs = 2000
    total = 0.0
    v = per_op_ceiling * 0.99
    max_age = policy_fn(v)
    for _ in range(runs):
        d = rng.uniform(0, ci) + rng.uniform(0, pl)
        # The verifier's evidence was fetched up to max_age before; it refreshes every max_age hours.
        phase = rng.uniform(0, max_age) if max_age > 0 else 0.0
        visible_at = detection_h + d  # revocation visible to a fresh fetch from this time on
        # first fetch at or after visible_at under a refresh period of max_age
        if max_age == 0:
            stop = visible_at
        else:
            k = math.ceil((visible_at - phase) / max_age)
            stop = phase + max(0, k) * max_age
        stop = max(stop, visible_at)
        n = rng.poisson(attack_rate_per_h * stop)
        spent = n * v
        if daily_ceiling is not None:
            days = math.ceil(stop / 24.0) if stop > 0 else 1
            spent = min(spent, daily_ceiling * days)
        total += spent
    return total / runs


def main():
    prm = PARAMS
    lam = prm["lambda_per_hour"]
    out = {"params": prm, "policies": {}, "pareto": [], "sensitivity": {}, "stolen_key": {}}
    flat = []
    for name, sweep in build_policies(lam).items():
        out["policies"][name] = []
        for label, fn in sweep:
            r = simulate(fn, prm["seed"], lam, prm)
            row = {"policy": name, "setting": label, "fetches_per_1000": round(r["fetches_per_1000"], 2), "expected_loss_per_1000_brl": round(r["expected_loss_per_1000_brl"], 4)}
            out["policies"][name].append(row)
            flat.append(row)
            if name == "consultar sempre":
                out["value_shape"] = {"top20_share_of_value": round(top_share(r["values"]), 3), "actions": r["actions"]}
            if name == "proporcional ao valor" and label == "L=1":
                fv = r["fetch_values"]
                cut = np.quantile(r["values"], 0.8)
                out["proportional_L1_fetches_on_top20_value"] = round(float((fv >= cut).mean()), 3)
    out["pareto"] = [flat[i] for i in sorted(pareto(flat), key=lambda i: flat[i]["fetches_per_1000"])]

    # Sensitivity: the true rate differs from the one the verifier assumed (lambda_assumed = 1e-5)
    for true_lam in (1e-6, 1e-5, 1e-4):
        rows = []
        for label, fn in (("prazo fixo 6 h", fixed(6.0)), ("proporcional L=1", proportional(1.0, lam, 24.0)), ("consultar sempre", fixed(0.0))):
            r = simulate(fn, prm["seed"], true_lam, prm)
            rows.append({"policy": label, "fetches_per_1000": round(r["fetches_per_1000"], 2), "expected_loss_per_1000_brl": round(r["expected_loss_per_1000_brl"], 4)})
        out["sensitivity"][f"{true_lam:g}"] = rows

    # Stolen key: per-operation ceiling R$ 5,000, attacker at 60 actions/h, detected after 12 h
    for label, fn in (("prazo fixo 6 h", fixed(6.0)), ("proporcional L=1", proportional(1.0, lam, 24.0)), ("consultar sempre", fixed(0.0))):
        out["stolen_key"][label] = {
            "sem teto diário": round(stolen_key(prm, fn, 5000, None, 12.0, 60.0, prm["seed"]), 0),
            "teto diário R$ 20.000": round(stolen_key(prm, fn, 5000, 20_000, 12.0, 60.0, prm["seed"]), 0),
        }

    # Credential evidence: the issuer publishes a revocation at once, so there is no publication delay.
    prm_c = {**prm, "no_publication_delay": True, "credentials": 200}
    flat_c = []
    for name, sweep in build_policies(lam).items():
        for label, fn in sweep:
            if name == "prazo fixo" and label not in ("0.25 h", "1 h", "6 h", "24 h"):
                continue
            r = simulate(fn, prm["seed"], lam, prm_c)
            flat_c.append({"policy": name, "setting": label, "fetches_per_1000": round(r["fetches_per_1000"], 2), "expected_loss_per_1000_brl": round(r["expected_loss_per_1000_brl"], 4)})
    out["credential_no_delay"] = {"rows": flat_c, "pareto": [flat_c[i] for i in sorted(pareto(flat_c), key=lambda i: flat_c[i]["fetches_per_1000"])]}

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: out[k] for k in ("value_shape", "proportional_L1_fetches_on_top20_value", "stolen_key")}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
