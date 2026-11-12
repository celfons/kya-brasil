"""
Sensitivity factors taken from the data, instead of round multipliers.

The measured revocation rate (lambda) is a floor and an average. The sensitivity analysis (sensitivity.py) repeats
the policy comparison at multiples of it; this script derives those multiples from the collection itself, so that
every factor the paper uses has a stated origin:

  month_peak_over_mean   peak month of end-user revocations / mean month (complete months of the measured year):
                         how far a bad month departs from the average the policies are calibrated on.
  flow_over_stock        rate by the flow of new CRL entries / rate by the stock (monthly counts over active
                         certificates): how much the stock rate under-counts because expired certificates leave the
                         CRL. Below 1 when the flow window is short; reported as is.
  ac_relative_hazard_max for each in-force end-user list with at least MIN_ENTRIES entries, its share of the new
                         entries seen by the collector / its share of the stock of entries; the maximum over lists.
                         A proxy for how much the rate of one AC exceeds the average (no per-AC denominator exists:
                         the ITI holds no per-AC counts), labelled as such. Only lists watched for about as long as
                         the longest-watched one are compared (window of at least WINDOW_SHARE of the longest):
                         a list that entered the collection later saw fewer hours, and on the test cut of 7 Nov
                         2026 only a weekend, so its few new entries would inflate the share of the others.

factor_max is the largest of the three, rounded to one decimal; sensitivity.py adds it to its grid, and the paper
cites it as the measured bound of the sensitivity range.

The rate also errs the other way: it counts every revocation, and only part of them is a compromise. factor_min is
the share of key compromise among the entries that state a reason (data/reasons.json), rounded to two decimals:
what the rate of compromise would be if the lists that give no reason behaved like those that do. It is an upper
reading of that share, since one AC marks every entry with a reason as key compromise.

    python3 -I fetch_factors.py   # reads data/measured.json, data/flow.json and data/reasons.json; writes data/factors.json
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
sys.path.insert(0, HERE)

MIN_ENTRIES = 1000
WINDOW_SHARE = 0.9
GRID = (1, 3, 10, 30, 100)


def main():
    import simulate_measured as M

    with open(os.path.join(DATA, "measured.json"), encoding="utf-8") as f:
        m = json.load(f)
    with open(os.path.join(DATA, "flow.json"), encoding="utf-8") as f:
        flow = json.load(f)

    lam = M.lambda_per_hour(m)
    months = lam["months"]
    peak_month = max(months, key=months.get)
    month_peak_over_mean = months[peak_month] / lam["per_month_mean"]

    flow_over_stock = flow["lambda_flow_per_year"] / lam["per_year"]

    longest = max((v.get("window_h") or 0.0) for v in flow["per_source"].values() if v.get("in_force"))
    per = {k: v for k, v in flow["per_source"].items()
           if v.get("in_force") and v.get("entries", 0) >= MIN_ENTRIES and v.get("new_entries") is not None
           and (v.get("window_h") or 0.0) >= WINDOW_SHARE * longest}
    stock_total = sum(v["entries"] for v in per.values())
    new_total = sum(v["new_entries"] for v in per.values())
    hazards = {}
    for k, v in per.items():
        share_new = v["new_entries"] / new_total if new_total else 0.0
        share_stock = v["entries"] / stock_total
        hazards[k] = {"ac": v["ac"], "entries": v["entries"], "new_entries": v["new_entries"], "relative_hazard": share_new / share_stock}
    top = max(hazards, key=lambda k: hazards[k]["relative_hazard"]) if hazards else None
    ac_relative_hazard_max = hazards[top]["relative_hazard"] if top else None

    candidates = [x for x in (month_peak_over_mean, flow_over_stock, ac_relative_hazard_max) if x is not None]
    factor_max = round(max(candidates), 1)
    with open(os.path.join(DATA, "reasons.json"), encoding="utf-8") as f:
        compromise_share = json.load(f)["total"]["key_compromise_share_of_with_reason"]
    factor_min = round(compromise_share, 2)
    multipliers = sorted(set(GRID) | ({factor_max} if factor_max > 1 else set()) | ({factor_min} if 0 < factor_min < 1 else set()))

    out = {
        "source": {"measured": "data/measured.json", "flow": "data/flow.json", "flow_fetched_at": flow["fetched_at"]},
        "month_peak_over_mean": round(month_peak_over_mean, 3), "peak_month": peak_month, "months_used": sorted(months),
        "flow_over_stock": round(flow_over_stock, 3), "lambda_stock_per_year": lam["per_year"], "lambda_flow_per_year": flow["lambda_flow_per_year"],
        "ac_relative_hazard_max": round(ac_relative_hazard_max, 3) if ac_relative_hazard_max is not None else None,
        "ac_relative_hazard_top": hazards.get(top), "ac_relative_hazards": hazards, "min_entries": MIN_ENTRIES,
        "window_share": WINDOW_SHARE, "longest_window_h": longest,
        "factor_max": factor_max, "key_compromise_share_of_with_reason": compromise_share, "factor_min": factor_min,
        "multipliers": multipliers,
        "note": "ac_relative_hazard is a proxy (share of new entries over share of stock, among lists watched for a comparable time); the ITI keeps no per-AC active counts",
    }
    with open(os.path.join(DATA, "factors.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: out[k] for k in ("month_peak_over_mean", "peak_month", "flow_over_stock", "ac_relative_hazard_max", "factor_max", "multipliers")}, ensure_ascii=False))
    if top:
        print("top AC:", hazards[top]["ac"], hazards[top]["relative_hazard"])


if __name__ == "__main__":
    main()
