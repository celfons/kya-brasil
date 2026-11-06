"""
Scale of the value of the agents' actions, from public Pix data, shared by the simulations.

There is no public data on what AI agents buy. Agents pay mostly by Pix and by credit card, the two means with the
easiest programmatic access, and the Central Bank publishes both (open data). Each scenario takes value AND rate from
its own source:
  - Pix: payments between different companies (data/pix_cnae.json, fetch_pix_cnae.py, mesmatit = N) for the value,
    Pix paid per paying company per hour (data/pix_rate.json, fetch_pix_rate.py) for the rate; the main scenario;
  - card: company credit cards, Empresarial and Corporativo (data/cards.json, fetch_cards.py), for both;
  - P2B (people to companies, data/pix.json) stays available for reference.
The rates are human baselines: how companies and their cards are used today.
The value keeps the log-normal shape of simulate.py. Its sigma (1.6, about 80% of the value in the top 20% of
actions) is above the lower bound the CNAE data gives (spread of the group means, fetch_pix_cnae.py); the median is
set so that the log-normal mean equals the Pix mean: median = mean * exp(-sigma^2 / 2).
"""
import json
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SIGMA = 1.6


def _load(name):
    with open(os.path.join(HERE, "data", name), encoding="utf-8") as f:
        return json.load(f)


def means():
    return {"B2B": _load("pix_cnae.json")["mean_brl"], "CARD": _load("cards.json")["mean_brl"],
            "P2B": _load("pix.json")["by_nature"]["P2B"]["mean_brl"]}


def rate(nature="B2B"):
    """Actions per hour per credential observed for that means of payment (human baseline)."""
    return {"B2B": _load("pix_rate.json")["per_company_per_hour"], "CARD": _load("cards.json")["transactions_per_card_per_hour"]}[nature]


def credentials_for(rate_per_hour, base_credentials=400, base_rate=2.0):
    """Credentials to simulate so a run has about as many actions as the 400 x 2/h of simulate.py."""
    return max(1, round(base_credentials * base_rate / rate_per_hour))


def sigma_lower_bound():
    return _load("pix_cnae.json")["sigma_between_groups"]


def median(nature="B2B", sigma=SIGMA):
    return round(means()[nature] * math.exp(-sigma ** 2 / 2), 2)
