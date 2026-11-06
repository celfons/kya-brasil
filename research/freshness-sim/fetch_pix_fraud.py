"""
Fraud in Pix, from the Central Bank's open data, as an external yardstick for the loss the freshness simulation
reports: how much of the value paid by Pix ends up as fraud the system accepts as such.

    python3 -I fetch_pix_fraud.py   # standard library only; writes data/pix_fraud.json

Sources (Banco Central do Brasil, Dados Abertos, Pix_DadosAbertos):
  - EstatisticasFraudesPix: monthly contested Pix accepted as fraud (count and value) and the rate per 100,000 Pix;
  - EstatisticasTransacoesPix: monthly value and count of all Pix, for the same months.
The 12 most recent months with fraud statistics are used. EXPLORATORY: a contested Pix accepted as fraud is not a
revoked certificate; the comparison gives the order of magnitude of a loss the payment system already lives with.
"""
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "pix_fraud.json")
BASE = "https://olinda.bcb.gov.br/olinda/servico/Pix_DadosAbertos/versao/v1/odata/"
MONTHS = 12


def get(entity, database, extra):
    q = {"@Database": f"'{database}'", "$format": "json", "$top": "1000000", **extra}
    url = BASE + entity + "(Database=@Database)?" + urllib.parse.urlencode(q, safe="@$'(),", quote_via=urllib.parse.quote)
    with urllib.request.urlopen(url, timeout=300) as r:  # fixed host; nothing from the arguments goes into the URL
        return json.load(r)["value"]


def month_back(yyyymm, n):
    y, m = divmod(int(yyyymm[:4]) * 12 + int(yyyymm[4:]) - 1 - n, 12)
    return f"{y:04d}{m + 1:02d}"


def main():
    now = datetime.now(timezone.utc)
    start = month_back(now.strftime("%Y%m"), 24)
    fraud = {str(x["AnoMes"]): x for x in get("EstatisticasFraudesPix", start, {
        "$select": "AnoMes,Qtdecontestacoesaceitas,ValorPixcontestadosaceitos,Qtdecontestacoesaceitasacada100mil"})}
    months = sorted(fraud)[-MONTHS:]
    out = {"source": BASE, "fetched_at": now.isoformat(timespec="seconds"), "months": {}}
    tf = tv = tn = tq = 0.0
    for mo in months:
        rows = [x for x in get("EstatisticasTransacoesPix", mo, {"$select": "AnoMes,VALOR,QUANTIDADE"}) if str(x["AnoMes"]) == mo]
        v, n = sum(x["VALOR"] for x in rows), sum(x["QUANTIDADE"] for x in rows)
        f = fraud[mo]
        out["months"][mo] = {"fraud_count": f["Qtdecontestacoesaceitas"], "fraud_value_brl": f["ValorPixcontestadosaceitos"],
                             "fraud_per_100k": f["Qtdecontestacoesaceitasacada100mil"], "pix_value_brl": round(v, 2), "pix_count": n}
        tf += f["ValorPixcontestadosaceitos"]
        tq += f["Qtdecontestacoesaceitas"]
        tv += v
        tn += n
    out["total"] = {"first": months[0], "last": months[-1], "fraud_value_brl": round(tf, 2), "pix_value_brl": round(tv, 2),
                    "fraud_share_of_value": tf / tv, "fraud_count": tq, "pix_count": tn, "fraud_per_100k": 1e5 * tq / tn}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps(out["total"], ensure_ascii=False))


if __name__ == "__main__":
    main()
