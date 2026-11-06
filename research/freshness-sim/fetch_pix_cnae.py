"""
Pix payments between companies by the receiver's economic sector (CNAE section), size and form of initiation, from
the Central Bank's open data, to estimate how spread out the value of a company's payments is.

    python3 -I fetch_pix_cnae.py   # standard library only; writes data/pix_cnae.json

Source: Banco Central do Brasil, Dados Abertos, Pix_DadosAbertos / CnaePorteRecebedor (monthly value and count of
settled Pix by receiver CNAE section, size, MEI, form of initiation, purpose and nature). Only B2B payments between
different owners (mesmatit = N) are kept: a company paying another company, not moving its own money.

The service has no value bands, only a mean per group. If each group's values are log-normal with a common shape
sigma_w, the log of a group's mean is the log of its median plus sigma_w^2 / 2, so the spread of log(group mean)
across groups, weighted by count, equals the spread of the group medians. Values vary inside each group too, so this
between-group spread is a LOWER BOUND of the sigma of the whole distribution. EXPLORATORY: Pix payments are not
agents' purchases.
"""
import json
import math
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "pix_cnae.json")
BASE = "https://olinda.bcb.gov.br/olinda/servico/Pix_DadosAbertos/versao/v1/odata/CnaePorteRecebedor(Database=@Database)"
MONTHS = 12
KEY = ("cnssecao", "porte", "mei", "formainic", "finalidade")


def month_back(yyyymm, n):
    y, m = divmod(int(yyyymm[:4]) * 12 + int(yyyymm[4:]) - 1 - n, 12)
    return f"{y:04d}{m + 1:02d}"


def fetch(month):
    q = {"@Database": f"'{month}'", "$filter": "naturezarel eq 'B2B' and mesmatit eq 'N'",
         "$select": "AnoMes," + ",".join(KEY) + ",qtlanliq,vllanliq", "$format": "json", "$top": "1000000"}
    url = BASE + "?" + urllib.parse.urlencode(q, safe="@$'(),", quote_via=urllib.parse.quote)
    with urllib.request.urlopen(url, timeout=300) as r:  # fixed host; nothing from the arguments goes into the URL
        rows = json.load(r)["value"]
    return [x for x in rows if str(x["AnoMes"]) == month]


def weighted_sd(xs, ws):
    tw = sum(ws)
    mu = sum(x * w for x, w in zip(xs, ws)) / tw
    return math.sqrt(sum(w * (x - mu) ** 2 for x, w in zip(xs, ws)) / tw)


def main():
    now = datetime.now(timezone.utc)
    last = month_back(now.strftime("%Y%m"), 1)  # the current month is incomplete
    months = [month_back(last, i) for i in range(MONTHS)][::-1]
    groups = {}
    for mo in months:
        for x in fetch(mo):
            if not x["qtlanliq"] or x["vllanliq"] is None or x["vllanliq"] <= 0:
                continue
            g = groups.setdefault(tuple(x[k] for k in KEY), [0.0, 0])
            g[0] += float(x["vllanliq"])
            g[1] += int(x["qtlanliq"])
    total_v = sum(v for v, _ in groups.values())
    total_n = sum(n for _, n in groups.values())
    logs = [math.log(v / n) for v, n in groups.values()]
    counts = [n for _, n in groups.values()]
    by_section = {}
    for key, (v, n) in groups.items():
        s = by_section.setdefault(key[0], [0.0, 0])
        s[0] += v
        s[1] += n
    out = {
        "source": BASE, "fetched_at": now.isoformat(timespec="seconds"), "months": months,
        "filter": "naturezarel = B2B, mesmatit = N", "group_key": list(KEY), "groups": len(groups),
        "value_brl": round(total_v, 2), "count": total_n, "mean_brl": round(total_v / total_n, 2),
        "sigma_between_groups": round(weighted_sd(logs, counts), 3),
        "by_section_mean_brl": {k: round(v / n, 2) for k, (v, n) in sorted(by_section.items(), key=lambda kv: -kv[1][1])},
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: out[k] for k in ("groups", "count", "mean_brl", "sigma_between_groups")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
