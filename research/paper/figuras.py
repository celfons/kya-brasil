"""Gera as figuras e os números do artigo a partir de data/ (cópia dos dados arquivados no Zenodo).

Uso: python3 scripts/figuras.py   (escreve figs/*.pdf e figs/numeros.tex)
"""
import csv
import re
import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
FIGS = ROOT / "figs"
FIGS.mkdir(exist_ok=True)
plt.rcParams.update({"font.size": 9, "font.family": "serif", "axes.spines.top": False, "axes.spines.right": False})

# Revogações por ano (LCR de usuário final)
anos = Counter()
for r in csv.DictReader(open(DATA / "monthly.csv", encoding="utf-8")):
    if r["tipo"] == "usuario-final":
        anos[r["mes"][:4]] += int(r["revogacoes"])
xs = sorted(anos)
fig, ax = plt.subplots(figsize=(4.6, 2.2))
ax.bar(xs, [anos[x] for x in xs], color="#4a6fa5")
ax.set_ylabel("revogações")
ax.tick_params(axis="x", rotation=60)
fig.tight_layout()
fig.savefig(FIGS / "revogacoes-ano.pdf")

# Dia da semana × hora (horário de Brasília)
grid = [[0] * 24 for _ in range(7)]
nomes = [""] * 7
for r in csv.DictReader(open(DATA / "weekday_hour.csv", encoding="utf-8")):
    d, h = int(r["weekday"]), int(r["hour_brt"])
    grid[d][h] = int(r["revocations"])
    nomes[d] = r["dia"]
fig, ax = plt.subplots(figsize=(6.0, 2.6))
im = ax.imshow(grid, aspect="auto", cmap="Blues")
ax.set_yticks(range(7), nomes)
ax.set_xticks(range(0, 24, 3))
ax.set_xlabel("hora (horário de Brasília)")
fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
fig.tight_layout()
fig.savefig(FIGS / "dia-hora.pdf")

# Números citados no texto
res = json.load(open(DATA / "results_measured.json", encoding="utf-8"))
cf = res["counterfactual"]["medido (reemissão 0,5 h)"]
wh = res["weekday_hour"]
lam = res["lambda"]
from decimal import ROUND_HALF_UP, Decimal  # noqa: E402


def _r(x, d):
    return float(Decimal(str(x)).quantize(Decimal(1).scaleb(-d), rounding=ROUND_HALF_UP))


br = lambda x, d=1: f"{_r(x, d):,.{d}f}".replace(",", "X").replace(".", ",").replace("X", ".")  # noqa: E731
macros = {
    "TotalRevog": br(wh["total"], 0),
    "PctComercial": br(100 * wh["business_share"], 0),
    "PctHorasComerciais": br(100 * wh["business_hours_share_of_week"], 0),
    "PctFimDeSemana": br(100 * wh["weekend_share"], 1),
    "RevogMes": br(lam["per_month_mean"], 0),
    "Ativos": br(lam["active"], 0),
    "LambdaAno": br(100 * lam["per_year"], 2),
    "JanelaMedia": br(cf["mean_h"]),
    "JanelaMediana": br(cf["p50_h"]),
    "JanelaPnoventaecinco": br(cf["p95_h"]),
    "JanelaSexta": br(cf["friday_19h"]["mean_h"]),
    "JanelaPior": br(cf["worst_slot"]["mean_h"]),
    "JanelaPiorDia": {"seg": "segunda-feira", "ter": "terça-feira", "qua": "quarta-feira", "qui": "quinta-feira", "sex": "sexta-feira", "sab": "sábado", "dom": "domingo"}[cf["worst_slot"]["weekday"]],
    "JanelaPiorHora": str(cf["worst_slot"]["hour_brt"]),
    "JanelaComercial": br(cf["business_hours_mean_h"]),
    "JanelaForaComercial": br(cf["off_hours_mean_h"]),
}
with open(FIGS / "numeros.tex", "w", encoding="utf-8") as f:
    f.write("% Gerado por scripts/figuras.py; não editar à mão.\n")
    for k, v in macros.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print("\n".join(f"{k} = {v}" for k, v in macros.items()))

# Fronteira de Pareto: consultas × perda esperada por 1.000 ações (cenário medido)
cen = res["scenarios"]["medido"]["rows"]
pts = [(r["fetches_per_1000"], r["expected_loss_per_1000_brl"], r["policy"], r["setting"]) for r in cen]
frente = []
for p in sorted(pts, key=lambda p: (p[0], p[1])):
    if not frente or p[1] < frente[-1][1] - 1e-9:
        frente.append(p)
estilos = {"consultar sempre": ("s", "#333333"), "prazo fixo": ("o", "#4a6fa5"), "proporcional ao valor": ("^", "#c0504d"), "faixas de valor": ("D", "#9bbb59")}
fig, ax = plt.subplots(figsize=(4.6, 2.6))
for pol, (m, c) in estilos.items():
    sel = [p for p in pts if p[2] == pol]
    ax.scatter([p[0] for p in sel], [p[1] for p in sel], marker=m, color=c, s=16, label=pol, zorder=3)
ax.plot([p[0] for p in frente], [p[1] for p in frente], color="#999999", lw=0.8, zorder=2)
ax.set_xscale("log")
from matplotlib.ticker import FixedLocator, NullFormatter, ScalarFormatter  # noqa: E402

ax.xaxis.set_major_locator(FixedLocator([20, 50, 100, 200, 500, 1000]))
ax.xaxis.set_major_formatter(ScalarFormatter())
ax.xaxis.set_minor_formatter(NullFormatter())
ax.set_xlabel("consultas ao status por 1.000 ações")
ax.set_ylabel("perda esperada (R\\$/1.000 ações)")
ax.legend(fontsize=7, frameon=False)
prop_frente = [p for p in frente if p[2] == "proporcional ao valor"]
fixo12 = next(p for p in pts if p[2] == "prazo fixo" and p[3] == "12 h")
# L principal da política proporcional: a régua da fraude do Pix (fração do valor perdida com fraude aceita ×
# valor médio do Pix entre empresas), a mesma conta de kya-brasil/research/freshness-sim/simulate.py (fraud_ruler_L)
_fraude = json.load(open(DATA / "pix_fraud.json", encoding="utf-8"))["total"]["fraud_share_of_value"]
_meanb2b = json.load(open(DATA / "scenarios.json", encoding="utf-8"))["means_brl"]["B2B"]
L_FRAUDE = round(_fraude * _meanb2b, 2)
L_ROTULO = f"L={L_FRAUDE:g}"
propL = next(p for p in pts if p[2] == "proporcional ao valor" and p[3] == L_ROTULO)
# Os dois pontos que o texto compara, rotulados na figura
for p_, txt, dx, dy in ((propL, f"$L$ = {L_FRAUDE:.2f}".replace(".", ","), 4, 6), (fixo12, "12 h", 4, -10)):
    ax.annotate(txt, (p_[0], p_[1]), xytext=(dx, dy), textcoords="offset points", fontsize=7)
fig.tight_layout()
fig.savefig(FIGS / "pareto.pdf")
fixo24 = next(p for p in pts if p[2] == "prazo fixo" and p[3] == "24 h")
prop001 = next(p for p in pts if p[2] == "proporcional ao valor" and p[3] == "L=0.01")
# Onde a política morde: acima de L/(λ·24 h) a idade máxima fica abaixo do teto de 24 h da biblioteca
from statistics import NormalDist  # noqa: E402
import math  # noqa: E402

_lam_h = lam["per_hour"]
_vs = json.load(open(DATA / "scenarios.json", encoding="utf-8"))["scenarios"][0]
corte = L_FRAUDE / (_lam_h * 24.0)
acima = 1 - NormalDist().cdf(math.log(corte / _vs["median_brl"]) / _vs["sigma"])
# O mesmo corte para os extremos da faixa de L exibida (R$ 0,01 e R$ 10): a conclusão é enunciada para a faixa,
# não para o ponto da régua da fraude.
_corte_L = lambda L: L / (_lam_h * 24.0)  # noqa: E731
_acima_L = lambda L: 1 - NormalDist().cdf(math.log(_corte_L(L) / _vs["median_brl"]) / _vs["sigma"])  # noqa: E731
extra = {
    "PerdaPiso": br(pts[0][1], 2),
    "LFraude": br(L_FRAUDE, 2),
    "PropConsultas": br(propL[0], 0),
    "PropPerda": br(propL[1], 2),
    "FixoVinteQuatroConsultas": br(fixo24[0], 0),
    "FixoVinteQuatroPerda": br(fixo24[1], 2),
    "PropUmConsultas": br(prop001[0], 0),
    "PropUmPerda": br(prop001[1], 2),
    "ValorCorte": br(round(corte, -3), 0),
    "ValorCorteCem": br(round(corte / 100, -1), 0),
    "PctAcoesAcimaCorte": br(100 * acima, 2),
    "LMetadeAcoes": br(_vs["median_brl"] * _lam_h * 24.0, 3),
    # Segunda régua, independente: fraude em cartões por valor nos EUA (Fed, 2016) sobre o valor médio do cenário de cartão.
    "CartaoEUAbps": br(json.load(open(DATA / "card_fraud.json", encoding="utf-8"))["card_fraud_bps_of_value"], 1),
    "LCartaoEUA": br(json.load(open(DATA / "card_fraud.json", encoding="utf-8"))["card_fraud_bps_of_value"] / 1e4 * json.load(open(DATA / "scenarios.json", encoding="utf-8"))["means_brl"]["CARD"], 2),
    "PixFraudeBps": br(1e4 * json.load(open(DATA / "pix_fraud.json", encoding="utf-8"))["total"]["fraud_share_of_value"], 1),   # o L em que o corte iguala a mediana das ações
    "ValorCorteLMin": br(round(_corte_L(0.01), -2), 0),
    "ValorCorteLMax": br(round(_corte_L(10.0), -4), 0),
    "PctAcoesAcimaCorteLMin": br(100 * _acima_L(0.01), 1),
    "PctAcoesAcimaCorteLMax": br(100 * _acima_L(10.0), 3),
    "FixoDozeConsultas": br(fixo12[0], 0),
    "FixoDozePerda": br(fixo12[1], 2),
    "PropNaFrente": str(len(prop_frente)),
}
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print("frente:", [(p[2], p[3], round(p[0]), round(p[1], 2)) for p in frente])
print(extra)

# Desempenho (data/bench.json, cópia de kya-brasil/research/bench/results.json)
bench = json.load(open(DATA / "bench.json", encoding="utf-8"))
med = {r["id"]: r for r in bench["results"]}
sz = bench["sizes"]
env = bench["env"]
ms = lambda k, d=1: br(med[k]["median_ms"], d)  # noqa: E731
p95 = lambda k, d=1: br(med[k]["p95_ms"], d)  # noqa: E731
kb = lambda n: br(n / 1024, 1)  # noqa: E731
linhas = [
    ("Emissão com assinatura A1 (RSA-2048)", "issuance"),
    ("Verificação da credencial autoemitida", "verify_self_issued"),
    ("Verificação da coassinatura", "verify_company_will"),
    ("Assinatura da requisição pelo agente", "sign_request"),
    ("Verificação offline completa (requisição, mandato e ação)", "authenticate_offline"),
    ("Cadeia de delegação, profundidade 3", "delegation_depth_3"),
    (f"LCR real do SERPRO ({br(77319, 0)} entradas): leitura e verificação", "crl_serpro_verify"),
]
with open(FIGS / "desempenho.tex", "w", encoding="utf-8") as f:
    f.write("% Gerado por scripts/figuras.py a partir de data/bench.json; não editar à mão.\n\\newcommand{\\LinhasDesempenho}{%\n")
    for rot, k in linhas:
        d = 0 if med[k]["median_ms"] >= 100 else 1
        f.write(f"{rot} & {ms(k, d)} & {p95(k, d)} \\\\\n")
    f.write("}\n")
extra = {
    "BenchCPU": env["cpu"].replace("(R)", "").replace("  ", " ").strip(),
    "BenchNode": env["node"].lstrip("v"),
    "BenchCore": env["packages"]["@kya-brasil/core"],
    "LookupSerpro": br(med["crl_serpro_lookup"]["median_ms"] * 1000, 1),
    "TamCredencial": kb(sz["credential_json"]),
    "TamCabecalhos": kb(sz["request_headers_total"]),
    "TamCabecalhosCoass": kb(sz["request_headers_total_1_cosignature"]),
    "TamSerpro": br(sz["crl_serpro"] / 1024 / 1024, 1),
    "OfflineMs": ms("authenticate_offline"),
}
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)

# Compatibilidade das bibliotecas com as LCR reais (data/crl_compat.json, cópia de
# kya-brasil/research/crl-compat/results/results.json)
cc = json.load(open(DATA / "crl_compat.json", encoding="utf-8"))
libs = cc["libraries"]
nomes_lib = {"OpenSSL CLI": "OpenSSL", "Go crypto/x509": "Go \\texttt{crypto/x509}", "Python cryptography": "Python \\texttt{cryptography}",
             "@peculiar/x509": "\\texttt{@peculiar/x509}", "PKI.js": "PKI.js", "node-forge": "node-forge", "@kya-brasil/core": "Esta biblioteca"}
grupos = ["rsa_small", "rsa_large", "ecdsa_p521", "ecdsa_brainpool", "ed448", "ed521"]
with open(FIGS / "compat.tex", "w", encoding="utf-8") as f:
    f.write("% Gerado por scripts/figuras.py a partir de data/crl_compat.json; não editar à mão.\n\\newcommand{\\LinhasCompat}{%\n")
    for lib, nome in nomes_lib.items():
        t = libs[lib]
        ver = t["version"].lstrip("go")
        cel = [f"{t['groups'][g]['ok']}/{t['groups'][g]['n']}" for g in grupos]
        f.write(f"{nome} {ver} & " + " & ".join(cel) + f" & {t['end_entity_ok']}/{t['end_entity_n']} \\\\\n")
    f.write("}\n")
g0 = libs["@kya-brasil/core"]["groups"]
extra = {
    "CompatFontes": str(cc["crls"]),
    "CompatFontesTotal": str(cc["crls"] + len(cc["unreachable"])),
    "CompatVerificaveis": str(cc["verifiable"]),
    "CompatLimiar": br(cc["large_threshold"], 0),
    "CompatGrandes": str(g0["rsa_large"]["n"]),
    "CompatUF": str(libs["@kya-brasil/core"]["end_entity_n"]),
    "CompatCoreOk": str(libs["@kya-brasil/core"]["total_ok"]),
    "CompatOpensslOk": str(libs["OpenSSL CLI"]["total_ok"]),
    "CompatPeculiarUF": str(libs["@peculiar/x509"]["end_entity_ok"]),
    "CompatPkijsUF": str(libs["PKI.js"]["end_entity_ok"]),
    "CompatData": cc["fetched_at"][:10],
}
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)

# Sensibilidade: ganho da política proporcional sobre o prazo fixo de mesmo número de consultas
# (data/sensitivity.json, cópia de kya-brasil/research/freshness-sim/sensitivity.json sem as linhas de cada política)
sens = json.load(open(DATA / "sensitivity.json", encoding="utf-8"))
fig, ax = plt.subplots(figsize=(4.6, 2.2))
nomes_escala = {v: k for k, v in sens.get("scales", {}).items()}
for med, (m, c) in zip(sens["medians_brl"], (("o", "#4a6fa5"), ("^", "#c0504d"))):
    sc = [s for s in sens["scenarios"] if s["median_brl"] == med and s["best"]]
    ax.plot([s["multiplier"] for s in sc], [100 * s["best"]["share_of_avoidable"] for s in sc], marker=m, color=c, ms=4, lw=1,
            label=f"{nomes_escala.get(med, 'mediana')} (mediana R\\$ {br(med, 0)})")
ax.set_xscale("log")
ax.set_xticks(sens["multipliers"], [f"{k}×" for k in sens["multipliers"]])
ax.set_xlabel("taxa de comprometimento (múltiplo da taxa medida)")
ax.set_ylabel("perda evitável\nremovida (%)")
ax.set_ylim(0, 100)
ax.legend(fontsize=7, frameon=False)
fig.tight_layout()
fig.savefig(FIGS / "sensibilidade.pdf")
pick = {(s["multiplier"], s["median_brl"]): s for s in sens["scenarios"]}
base_med = sens["medians_brl"][0]
um, cem = pick[(1, base_med)], pick[(100, base_med)]
extra = {
    "SensMultMax": str(max(sens["multipliers"])),
    "SensUmPct": br(100 * um["best"]["share_of_avoidable"], 0),
    "SensUmGanho": br(um["best"]["gain_brl_per_1000"], 2),
    "SensCemPct": br(100 * cem["best"]["share_of_avoidable"], 0),
    "SensCemGanho": br(cem["best"]["gain_brl_per_1000"], 0),
    "SensCemPiso": br(cem["floor_brl_per_1000"], 0),
}
for med in sens["medians_brl"][1:]:
    a, b = pick[(1, med)], pick[(100, med)]
    extra.update({"SensAltaMediana": br(med, 0), "SensAltaUmPct": br(100 * a["best"]["share_of_avoidable"], 0),
                  "SensAltaCemPct": br(100 * b["best"]["share_of_avoidable"], 0), "SensAltaCemGanho": br(b["best"]["gain_brl_per_1000"], 0)})
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)

# Quadro de sócios (data/qsa.json, cópia de kya-icp/analysis/qsa/results.json; dados abertos do CNPJ, out./2026)
qsa = json.load(open(DATA / "qsa.json", encoding="utf-8"))
cob = qsa["cobertura"]
todas = cob["TODAS"]["empresas"]
semei = {k: v for k, v in cob.items() if not k.startswith("_") and k not in ("TODAS", "MEI (2135 + opcao MEI)", "EI nao-MEI (2135)")}
n_semei = sum(v["empresas"] for v in semei.values())
adm_semei = sum(v["com_PF_qual_admin_dir_pres_socioadm"]["n"] for v in semei.values())
mei_ei = cob["MEI (2135 + opcao MEI)"]["empresas"] + cob["EI nao-MEI (2135)"]["empresas"]
extra = {
    "QsaAtivas": br(todas / 1e6, 1),
    "QsaCoberturaSemMei": br(100 * adm_semei / n_semei, 1),
    "QsaMeiEiPct": br(100 * mei_ei / todas, 0),
    "QsaLtda": br(cob["LTDA (2062)"]["com_PF_qual_admin_dir_pres_socioadm"]["pct"], 1),
    "QsaEntradaTresMeses": br(qsa["frescor_entrada"]["entrada_ultimos_3_meses"]["pct"], 1),
}
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)

# Cenários de robustez: escala do valor (Pix), dispersão e tráfego (cópia de kya-brasil/research/freshness-sim/scenarios.json
# sem as linhas de cada política)
cen = json.load(open(DATA / "scenarios.json", encoding="utf-8"))
por_nome = {c["name"]: c for c in cen["scenarios"]}
def faixa(vals, d):
    a, b = min(vals), max(vals)
    return br(a, d) if br(a, d) == br(b, d) else f"{br(a, d)}--{br(b, d)}"


def linha(rot, cs):
    m = lambda f, d: faixa([f(c) for c in cs], d)  # noqa: E731
    return (f"{rot} & {m(lambda c: c['median_brl'], 0)} & {m(lambda c: c['floor_brl_per_1000'], 2)} & "
            f"{m(lambda c: c['proportional_Lfraude']['fetches_per_1000'], 0)} & "
            f"{m(lambda c: c['proportional_Lfraude']['expected_loss_per_1000_brl'], 2)} & "
            f"{m(lambda c: c['fixed_12h']['fetches_per_1000'], 0)} & "
            f"{m(lambda c: c['fixed_12h']['expected_loss_per_1000_brl'], 2)} \\\\")


sig = [por_nome["sigma no limite inferior"], por_nome["sigma 2,0"]]
linhas = [
    linha("Pix entre empresas (principal)", [por_nome["principal"]]),
    linha("Cartão de crédito empresarial", [por_nome["cartão"]]),
    "\\midrule",
    linha(f"Pix, $\\sigma$ de {br(sig[0]['sigma'], 2)} a {br(sig[1]['sigma'], 1)}", sig),
    linha("Pix, 10 vezes o ritmo", [por_nome["Pix, 10 vezes o ritmo"]]),
    linha("Pix, 100 vezes o ritmo", [por_nome["Pix, 100 vezes o ritmo"]]),
    linha("Cartão, 100 vezes o ritmo", [por_nome["cartão, 100 vezes o ritmo"]]),
]
with open(FIGS / "cenarios.tex", "w", encoding="utf-8") as f:
    f.write("% Gerado por scripts/figuras.py; não editar à mão.\n\\newcommand{\\LinhasCenarios}{%\n" + "\n".join(linhas) + "}\n")
pr = por_nome["principal"]
ca = por_nome["cartão"]
taxa = json.load(open(DATA / "pix_rate.json", encoding="utf-8"))
cart = json.load(open(DATA / "cards.json", encoding="utf-8"))
fraude = json.load(open(DATA / "pix_fraud.json", encoding="utf-8"))["total"]["fraud_share_of_value"]
extra = {
    "PixBtoBMedia": br(cen["means_brl"]["B2B"], 0),
    "PixBtoBMediana": br(pr["median_brl"], 0),
    "PixRitmoMes": br(taxa["per_company_per_month"], 0),
    "PixRitmoHora": br(taxa["per_company_per_hour"], 2),
    "CartaoMedia": br(cen["means_brl"]["CARD"], 0),
    "CartaoMediana": br(ca["median_brl"], 0),
    "CartaoRitmoMes": br(cart["transactions_per_card_per_month"], 1),
    "CartaoTrimestres": f"{cart['quarters'][0]['quarter'][4:]}º trimestre de {cart['quarters'][0]['quarter'][:4]} ao {cart['quarters'][-1]['quarter'][4:]}º de {cart['quarters'][-1]['quarter'][:4]}",
    "SigmaInf": br(cen["sigma_lower_bound"], 2),
    "PixMeses": (lambda m: f"{m[0][4:]}/{m[0][:4]} a {m[-1][4:]}/{m[-1][:4]}")(json.load(open(DATA / "pix_cnae.json", encoding="utf-8"))["months"]),
    "PropNaFrenteMin": str(min(c["proportional_on_front"] for c in cen["scenarios"])),
}
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)

# Motivos das revogações (reasons.json), estabilidade da série de 2026 (monthly.csv), fraude no Pix (pix_fraud.json)
# e perda na cauda do cenário principal (scenarios.json)
mot = json.load(open(DATA / "reasons.json", encoding="utf-8"))
com_motivo = {k: v for k, v in mot["sources"].items() if v.get("reasons") and set(v["reasons"]) != {"sem motivo"}}
serasa = next(v for v in mot["sources"].values() if "Serasa" in v["ac"])
pct = lambda d: 100 * d["reasons"].get("key_compromise", 0) / (d["entries"] - d["reasons"].get("sem motivo", 0))  # noqa: E731
mensal = {}
with open(DATA / "monthly.csv", encoding="utf-8") as fm:
    for r in csv.DictReader(fm):
        if r["tipo"] == "usuario-final":
            mensal[r["mes"]] = mensal.get(r["mes"], 0) + int(r["revogacoes"])
m26 = [mensal[k] for k in sorted(mensal) if k.startswith("2026") and k < "2026-11"]
m25 = [mensal[k] for k in sorted(mensal) if k.startswith("2025")]
fr = json.load(open(DATA / "pix_fraud.json", encoding="utf-8"))["total"]
pr = por_nome["principal"]
linha_pr = lambda pol, st: next(r for r in pr["rows"] if r["policy"] == pol and r["setting"] == st)  # noqa: E731
assert all(c["proportional_Lfraude"]["setting"] == L_ROTULO for c in cen["scenarios"]), "scenarios.json com outro L"
perda_valor = pr["proportional_Lfraude"]["expected_loss_per_1000_brl"] / (1000 * cen["means_brl"]["B2B"])
cem = next(s_ for s_ in sens["scenarios"] if s_["multiplier"] == max(sens["multipliers"]) and s_["median_brl"] == sens["medians_brl"][0])
extra = {
    "MotivoKeyPct": br(100 * mot["total"]["key_compromise_share_of_with_reason"], 0),
    "MotivoComMotivoPct": br(100 * mot["total"]["with_reason"] / mot["total"]["entries"], 0),
    "MotivoSerasaPct": br(pct(serasa), 0),
    "MotivoNumAC": str(len(com_motivo)),
    "SerieDifPct": br(abs(100 * (sum(m26[-3:]) / sum(m26[:3]) - 1)), 0),
    "SerieVinteCincoPct": br(100 * (1 - (sum(m25) / len(m25)) / (sum(m26) / len(m26))), 0),
    "FraudePixPct": br(100 * fr["fraud_share_of_value"], 3),
    "FraudePixMeses": f"{fr['first'][4:]}/{fr['first'][:4]} a {fr['last'][4:]}/{fr['last'][:4]}",
    "FraudePorCemMil": br(fr["fraud_per_100k"], 1),
    "PerdaPctValor": br(100 * perda_valor, 4),
    "RazaoFraude": br(fr["fraud_share_of_value"] / perda_valor, 0),
    "RazaoFraudeCem": br(fr["fraud_share_of_value"] / (cem["floor_brl_per_1000"] / (1000 * cen["means_brl"]["B2B"])), 1),
    "CaudaSempre": br(linha_pr("consultar sempre", "0 h")["tail_loss_per_1000_tail_actions_brl"], 0),
    "CaudaProp": br(linha_pr("proporcional ao valor", L_ROTULO)["tail_loss_per_1000_tail_actions_brl"], 0),
    "CaudaPropConsultas": br(linha_pr("proporcional ao valor", L_ROTULO)["fetches_per_1000"], 0),
    "CaudaPropUm": br(linha_pr("proporcional ao valor", "L=0.01")["tail_loss_per_1000_tail_actions_brl"], 0),
    "CaudaVinteQuatro": br(linha_pr("prazo fixo", "24 h")["tail_loss_per_1000_tail_actions_brl"], 0),
    "CaudaFixoDoze": br(linha_pr("prazo fixo", "12 h")["tail_loss_per_1000_tail_actions_brl"], 0),
    "CaudaFixoSeis": br(linha_pr("prazo fixo", "6 h")["tail_loss_per_1000_tail_actions_brl"], 0),
    "FixoSeisConsultas": br(linha_pr("prazo fixo", "6 h")["fetches_per_1000"], 0),
    "CaudaPctPerda": br(100 * linha_pr("prazo fixo", "12 h")["tail_share_of_loss"], 0),
}
# Fatores de sensibilidade tirados dos dados (data/factors.json, scripts/fetch_factors.py do kya-brasil): pico mensal
# sobre a média, taxa pelo fluxo sobre a pelo estoque e a AC de maior risco relativo. O maior deles é o limite observado;
# 10 e 100 vezes ficam como teste de estresse além do observado.
try:
    fat = json.load(open(DATA / "factors.json", encoding="utf-8"))
    extra.update({
        "FatorMesPico": br(fat["month_peak_over_mean"], 2), "FatorMesPicoMes": fat["peak_month"],
        "FatorFluxoEstoque": br(fat["flow_over_stock"], 2),
        "FatorAcMax": br(fat["ac_relative_hazard_max"], 1), "FatorAcMaxNome": fat["ac_relative_hazard_top"]["ac"],
        "FatorMax": br(fat["factor_max"], 1),
    })
    fmax = next((s for s in sens["scenarios"] if s["median_brl"] == base_med and abs(s["multiplier"] - fat["factor_max"]) < 1e-9 and s["best"]), None)
    if fmax:
        extra.update({"SensFatorPct": br(100 * fmax["best"]["share_of_avoidable"], 0), "SensFatorGanho": br(fmax["best"]["gain_brl_per_1000"], 2)})
except FileNotFoundError:
    pass
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)

# OCSP na ICP-Brasil (data/ocsp.json): certificados de AC de segundo nível com ponto OCSP no AIA e hosts que resolvem.
_ocsp = json.load(open(DATA / "ocsp.json", encoding="utf-8"))
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    f.write(f"\\newcommand{{\\OcspAcCerts}}{{{_ocsp['ac_certificates']}}}\n")
    f.write(f"\\newcommand{{\\OcspComAia}}{{{_ocsp['with_ocsp_aia']}}}\n")
    f.write(f"\\newcommand{{\\OcspHostsResolvem}}{{{len(_ocsp['ocsp_hosts_resolving'])}}}\n")
    f.write(f"\\newcommand{{\\OcspHostsTotal}}{{{len(_ocsp['ocsp_hosts_resolving']) + len(_ocsp['ocsp_hosts_not_resolving'])}}}\n")

# Cobertura do coletor: AC da árvore do ITI (data/iti_estrutura.json, scripts/iti_estrutura.py) que as LCR de
# usuário final medidas (data/measured.json) representam. O nome da AC sai do id da fonte: "uf-ac-serpro-rfb-v5" →
# "AC SERPRO RFB", como o ITI escreve.
import re  # noqa: E402

iti = json.load(open(DATA / "iti_estrutura.json", encoding="utf-8"))
ac2 = [a for a in iti["ac"] if a["nivel"] == 2]
rfb = [a for a in ac2 if a["superior"] == "AC RFB"]
_medido = json.load(open(DATA / "measured.json", encoding="utf-8"))
fontes_uf, cadencia = _medido["weekday_hour_sources"], _medido["cadence_usuario_final"]
def nome_ac(fid: str) -> str:
    partes = fid.removeprefix("uf-ac-").split("-")
    while len(partes) > 1 and re.fullmatch(r"[vg]\d+", partes[-1]):
        partes.pop()
    return "AC " + " ".join(partes).upper()


# Onde o ITI escreve o nome de outro jeito, o id da fonte não basta: a tabela abaixo fecha a diferença.
ALIAS_ITI = {
    "AC ALTERNATIVE": "AC ALTERNATIVE TECNOLOGIA",
    "AC SAFE ID BRASIL": "AC SAFE-ID BRASIL",
    "AC SERPRO ACF": "SERPRO ACF",
    "AC REDEBRASIL": "AC REDE BRASIL",
    "AC CERTISIGN OM BR": "AC CERTISIGN_OM-BR",
    "AC SERASA CD": "SERASA CD",
    # Fora da árvore do ITI (AC descredenciada, LCR ainda publicada): coletada, mas não conta como cobertura.
    "AC SERASA JUS": None,
}
cobertas = {ALIAS_ITI.get(nome_ac(f), nome_ac(f)) for f in fontes_uf} - {None}
assert cobertas <= {a["nome"] for a in ac2}, cobertas - {a["nome"] for a in ac2}
extra = {
    "EstruturaData": iti["atualizado_em"],
    "AcPrimeiroNivel": str(sum(a["nivel"] == 1 for a in iti["ac"])),
    "AcSegundoNivel": str(len(ac2)),
    "AcSegundoCredenciadas": str(sum(a["situacao"] == 4002 for a in ac2)),
    "AcRfb": str(len(rfb)),
    "AcCobertas": str(len(cobertas)),
    "AcRfbCobertas": str(len(cobertas & {a["nome"] for a in rfb})),
    "LcrUsuarioFinal": str(len(fontes_uf)),
    "LcrVigentes": str(sum("encerrada" not in cadencia[f]["ac"] for f in fontes_uf)),
}
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)

# Taxa pelo fluxo e tabela por lista (data/flow.json, cópia de kya-brasil/research/freshness-sim/fetch_flow.py),
# restritas às listas do corte (data/measured.json), e os literais do texto que mudam a cada corte.
fluxo = json.load(open(DATA / "flow.json", encoding="utf-8"))
corte = _medido["generated_at"][:10]
MESES = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"]
data_pt = lambda d: f"{int(d[8:10])} de {MESES[int(d[5:7]) - 1]} de {d[:4]}"  # noqa: E731
listas = {k: v for k, v in fluxo["per_source"].items() if k in fontes_uf}
vig = {k: v for k, v in listas.items() if v["in_force"]}
bs = [v["business_share"] for v in listas.values() if v["business_share"] is not None and v["weekday_hour_total"] >= 100]
novas = sum(v["new_entries"] or 0 for v in vig.values())
por_hora = sum((v["new_entries"] or 0) / v["window_h"] for v in vig.values() if v["window_h"])
lam_fluxo_ano = por_hora * 24 * 365 / fluxo["active"]
anos = sorted({r["mes"][:4] for r in csv.DictReader(open(DATA / "monthly.csv", encoding="utf-8")) if r["tipo"] == "usuario-final"})
# Fontes configuradas no corte: as que o teste de compatibilidade do mesmo corte baixou ou tentou baixar
# (data/crl_compat.json), que é a lista de fontes do coletor naquele dia.
fontes_corte = cc["crls"] + len(cc["unreachable"])
extra = {
    "DataCorte": data_pt(corte),
    "MesCorte": f"{MESES[int(corte[5:7]) - 1]} de {corte[:4]}",
    "AnoCorte": corte[:4],
    "AnoInicio": anos[0],
    "FontesTotal": str(fontes_corte),
    "LcrEncerradas": str(len(fontes_uf) - sum("encerrada" not in cadencia[f]["ac"] for f in fontes_uf)),
    "PctComercialMin": br(100 * min(bs), 0),
    "PctComercialMax": br(100 * max(bs), 0),
    "FluxoData": data_pt(fluxo["fetched_at"][:10]),
    "FluxoHoras": br(max(v["window_h"] for v in vig.values()), 0),
    "FluxoNovas": br(novas, 0),
    "LambdaFluxoAno": br(100 * lam_fluxo_ano, 2),
    "ListasVigentes": str(len(vig)),
}
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)

# Tabela por lista vigente: nome, entradas, % em horário comercial, validade, novas na coleta, atraso mediano.
nome_lista = lambda ac: re.sub(r"\s*\(.*?\)", "", ac).replace("Autoridade Certificadora ", "AC ").replace("SERPRORFBv", "Serpro RFB v").replace("AC SOLUTI Multipla", "Soluti Múltipla").replace("Multipla", "Múltipla").replace("AC Certisign ", "Certisign ").replace("AC Serasa ", "Serasa ").replace("AC ", "")  # noqa: E731
linhas = []
for k, v in sorted(vig.items(), key=lambda kv: -kv[1]["entries"]):
    med = br(v["delay_median_h"], 2) if v["delay_median_h"] is not None else "--"
    # Campos ausentes (lista que a cryptography não decodifica, ou sem versão nova) viram "--".
    cel = lambda x, nd=0, mult=1: br(mult * x, nd) if x is not None else "--"  # noqa: E731
    linhas.append(f"{nome_lista(v['ac'])} & {br(v['entries'], 0)} & {cel(v['business_share'], 0, 100)} & {cel(v['validity_h'])} & {cel(v['new_entries'])} & {med} \\\\")
MAX_LINHAS = 12
if len(linhas) > MAX_LINHAS:
    resto = list(sorted(vig.values(), key=lambda v: -v["entries"]))[MAX_LINHAS:]
    linhas = linhas[:MAX_LINHAS] + [f"outras {len(resto)} listas & {br(sum(v['entries'] for v in resto), 0)} & -- & -- & {br(sum(v['new_entries'] or 0 for v in resto), 0)} & -- \\\\"]
with open(FIGS / "por-lista.tex", "w", encoding="utf-8") as f:
    f.write("% Gerado por scripts/figuras.py; não editar à mão.\n\\newcommand{\\LinhasPorLista}{%\n" + "\n".join(linhas) + "}\n")
print("\n".join(linhas))
