"""
Company credit cards (Empresarial and Corporativo products), from the Central Bank's open data, for the card scenario
of the freshness simulation: the mean value of a purchase and how often an active card is used.

    python3 -I fetch_cards.py   # standard library only; writes data/cards.json

Source: Banco Central do Brasil, Dados Abertos, MPV_DadosAbertos / Quantidadeetransacoesdecartoes (quarterly active
cards and domestic transactions, by brand, function, product and modality). Only credit cards of the Empresarial and
Corporativo products are kept: cards a company gives someone to spend in its name, with a limit, which is the closest
existing instrument to an agent's mandate. The last 4 quarters available are used. EXPLORATORY: these are people's
purchases with company cards, not agents' purchases; the rate is a human baseline.
"""
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "cards.json")
BASE = "https://olinda.bcb.gov.br/olinda/servico/MPV_DadosAbertos/versao/v1/odata/Quantidadeetransacoesdecartoes(trimestre=@trimestre)"
PRODUCTS = ("Empresarial", "Corporativo")
HOURS_PER_QUARTER = 24 * 365.25 / 4


def quarter(q):
    url = BASE + "?" + urllib.parse.urlencode({"@trimestre": f"'{q}'", "$format": "json", "$top": "5000"}, safe="@$'", quote_via=urllib.parse.quote)
    with urllib.request.urlopen(url, timeout=180) as r:  # fixed host; nothing from the arguments goes into the URL
        return [x for x in json.load(r)["value"] if x["trimestre"] == q]


def previous(q):
    y, n = int(q[:4]), int(q[4:])
    return f"{y - 1}4" if n == 1 else f"{y}{n - 1}"


def main():
    now = datetime.now(timezone.utc)
    q = f"{now.year}{(now.month - 1) // 3 + 1}"
    quarters = []
    while len(quarters) < 4 and q > "2020":
        q = previous(q)
        rows = [x for x in quarter(q) if x["nomeFuncao"] == "Crédito" and x["produto"] in PRODUCTS]
        if rows:
            quarters.append({"quarter": q, "active_cards": sum(x["qtdCartoesAtivos"] or 0 for x in rows),
                             "transactions": sum(x["qtdTransacoesNacionais"] or 0 for x in rows),
                             "value_brl": round(sum(x["valorTransacoesNacionais"] or 0 for x in rows), 2)})
    n = sum(x["transactions"] for x in quarters)
    v = sum(x["value_brl"] for x in quarters)
    per_card_hour = sum(x["transactions"] / x["active_cards"] for x in quarters) / len(quarters) / HOURS_PER_QUARTER
    out = {"source": BASE, "fetched_at": now.isoformat(timespec="seconds"), "products": PRODUCTS, "function": "Crédito",
           "quarters": sorted(quarters, key=lambda x: x["quarter"]), "mean_brl": round(v / n, 2),
           "transactions_per_card_per_hour": round(per_card_hour, 5), "transactions_per_card_per_month": round(per_card_hour * 24 * 365.25 / 12, 2)}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: out[k] for k in ("mean_brl", "transactions_per_card_per_hour", "transactions_per_card_per_month")}, ensure_ascii=False), [x["quarter"] for x in out["quarters"]])


if __name__ == "__main__":
    main()
