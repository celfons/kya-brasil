"""
Scale of the value of the agents' actions, from public Pix data, shared by the simulations.

There is no public data on what AI agents buy. The closest public measure of what a company pays or is paid per
transaction is Pix (Banco Central do Brasil, open data):
  - B2B: payments between different companies (data/pix_cnae.json, fetch_pix_cnae.py, mesmatit = N), the main scale;
  - P2B: payments from people to companies (data/pix.json, fetch_pix.py), the low scale.
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
    return {"B2B": _load("pix_cnae.json")["mean_brl"], "P2B": _load("pix.json")["by_nature"]["P2B"]["mean_brl"]}


def sigma_lower_bound():
    return _load("pix_cnae.json")["sigma_between_groups"]


def median(nature="B2B", sigma=SIGMA):
    return round(means()[nature] * math.exp(-sigma ** 2 / 2), 2)
