"""
How often a company pays by Pix, from the Central Bank's open data, for the Pix scenario of the freshness simulation.

    python3 -I fetch_pix_rate.py   # standard library only; writes data/pix_rate.json

Source: Banco Central do Brasil, Dados Abertos, Pix_DadosAbertos / TransacoesPixPorMunicipio (monthly count of Pix
paid by companies, QT_PagadorPJ, and of distinct paying companies, QT_PES_PagadorPJ, by the payer's municipality).
Each company is counted in its own municipality, so the sums over municipalities give the national figures. The rate
is Pix paid per paying company per hour, over the last 12 months available. EXPLORATORY: these are companies'
payments today, not agents'; the rate is a human baseline.
"""
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "pix_rate.json")
BASE = "https://olinda.bcb.gov.br/olinda/servico/Pix_DadosAbertos/versao/v1/odata/TransacoesPixPorMunicipio(DataBase=@DataBase)"
MONTHS = 12


def month_back(yyyymm, n):
    y, m = divmod(int(yyyymm[:4]) * 12 + int(yyyymm[4:]) - 1 - n, 12)
    return f"{y:04d}{m + 1:02d}"


def month(mo):
    q = {"@DataBase": f"'{mo}'", "$format": "json", "$top": "20000", "$select": "AnoMes,QT_PagadorPJ,QT_PES_PagadorPJ"}
    url = BASE + "?" + urllib.parse.urlencode(q, safe="@$'(),", quote_via=urllib.parse.quote)
    with urllib.request.urlopen(url, timeout=300) as r:  # fixed host; nothing from the arguments goes into the URL
        rows = [x for x in json.load(r)["value"] if str(x["AnoMes"]) == mo]
    return sum(x["QT_PagadorPJ"] or 0 for x in rows), sum(x["QT_PES_PagadorPJ"] or 0 for x in rows), len(rows)


def main():
    now = datetime.now(timezone.utc)
    last = month_back(now.strftime("%Y%m"), 1)
    out = {"source": BASE, "fetched_at": now.isoformat(timespec="seconds"), "months": {}}
    rates = []
    for mo in [month_back(last, i) for i in range(MONTHS + 2)][::-1]:
        pix, payers, municipalities = month(mo)
        if not payers:
            continue
        hours = 24 * (datetime(int(mo[:4]) + (mo[4:] == "12"), int(mo[4:]) % 12 + 1, 1) - datetime(int(mo[:4]), int(mo[4:]), 1)).days
        out["months"][mo] = {"pix_paid_by_companies": pix, "paying_companies": payers, "municipalities": municipalities,
                             "per_company_per_month": round(pix / payers, 2)}
        rates.append(pix / payers / hours)
    keep = sorted(out["months"])[-MONTHS:]
    out["months"] = {k: out["months"][k] for k in keep}
    rates = rates[-MONTHS:]
    out["per_company_per_hour"] = round(sum(rates) / len(rates), 5)
    out["per_company_per_month"] = round(sum(v["per_company_per_month"] for v in out["months"].values()) / len(keep), 2)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: out[k] for k in ("per_company_per_hour", "per_company_per_month")}), keep[0], keep[-1])


if __name__ == "__main__":
    main()
