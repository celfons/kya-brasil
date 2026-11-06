"""
Mean transaction value of Pix payments to companies (B2B and P2B), from the Central Bank's open data, to anchor the
value distribution of the freshness simulation in a public figure instead of a placeholder median.

    python3 -I fetch_pix.py   # standard library only; writes data/pix.json

Source: Banco Central do Brasil, Dados Abertos, Pix_DadosAbertos / EstatisticasTransacoesPix (monthly totals of value
and count by payer and receiver type, region, age, initiation and nature). The service has no value bands, so only
the mean value per transaction is used; the simulation keeps its log-normal shape and sets the scale from this mean.
EXPLORATORY: Pix payments are not agents' purchases; they are the closest public measure of what a company pays or is
paid per transaction.
"""
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "pix.json")
BASE = "https://olinda.bcb.gov.br/olinda/servico/Pix_DadosAbertos/versao/v1/odata/EstatisticasTransacoesPix(Database=@Database)"
NATURES = ("B2B", "P2B")  # company to company, person to company
MONTHS = 12  # the last 12 months available


def month_back(yyyymm, n):
    y, m = divmod(int(yyyymm[:4]) * 12 + int(yyyymm[4:]) - 1 - n, 12)
    return f"{y:04d}{m + 1:02d}"


def fetch(month, nature):
    q = {"@Database": f"'{month}'", "$filter": f"NATUREZA eq '{nature}'", "$select": "AnoMes,VALOR,QUANTIDADE",
         "$format": "json", "$top": "100000"}
    url = BASE + "?" + urllib.parse.urlencode(q, safe="@$'(),", quote_via=urllib.parse.quote)
    with urllib.request.urlopen(url, timeout=120) as r:  # fixed host; nothing from the arguments goes into the URL
        rows = json.load(r)["value"]
    rows = [x for x in rows if str(x["AnoMes"]) == month]
    return {"value_brl": round(sum(x["VALOR"] for x in rows), 2), "count": int(sum(x["QUANTIDADE"] for x in rows))}


def main():
    now = datetime.now(timezone.utc)
    last = month_back(now.strftime("%Y%m"), 1)  # the current month is incomplete
    months = [month_back(last, i) for i in range(MONTHS)][::-1]
    out = {"source": BASE, "fetched_at": now.isoformat(timespec="seconds"), "months": {}, "by_nature": {}}
    for nat in NATURES:
        tv = tc = 0
        for mo in months:
            r = fetch(mo, nat)
            if r["count"] == 0:
                continue
            out["months"].setdefault(mo, {})[nat] = {**r, "mean_brl": round(r["value_brl"] / r["count"], 2)}
            tv += r["value_brl"]
            tc += r["count"]
        out["by_nature"][nat] = {"value_brl": round(tv, 2), "count": tc, "mean_brl": round(tv / tc, 2) if tc else None}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps(out["by_nature"], ensure_ascii=False))


if __name__ == "__main__":
    main()
