"""Gera as figuras e os números do artigo a partir dos resultados deste repositório.

Cópia pública de kya-paper/scripts/figuras.py. Lê os resultados que os scripts de research/ escrevem e
data/monthly.csv (cópia do conjunto de dados DOI 10.5281/zenodo.23977027), e escreve em out/ as figuras (PDF),
out/numeros.tex (macros com os números citados no texto), out/desempenho.tex e out/compat.tex (linhas das tabelas).

Uso: python3 -I research/paper/figuras.py   (precisa de matplotlib)
"""
import csv
import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parent
MONTHLY = HERE / "data" / "monthly.csv"
WEEKDAY_HOUR = RESEARCH / "freshness-sim" / "data" / "weekday_hour.csv"
MEASURED = RESEARCH / "freshness-sim" / "results_measured.json"
BENCH = RESEARCH / "bench" / "results.json"
CRL_COMPAT = RESEARCH / "crl-compat" / "results" / "results.json"
SENSITIVITY = RESEARCH / "freshness-sim" / "sensitivity.json"
PROP = "proporcional ao valor"
CORE = "@kya-brasil/core"
PKIJS = "PKI.js"
FIGS = HERE / "out"
FIGS.mkdir(exist_ok=True)
NUMEROS = FIGS / "numeros.tex"


def write_macros(macros, mode="a"):
    """Writes one \\newcommand per number to out/numeros.tex ("w" starts the file)."""
    with open(NUMEROS, mode, encoding="utf-8") as f:
        if mode == "w":
            f.write("% Gerado por research/paper/figuras.py; não editar à mão.\n")
        for k, v in macros.items():
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")


plt.rcParams.update({"font.size": 9, "font.family": "serif", "axes.spines.top": False, "axes.spines.right": False})

# Revogações por ano (LCR de usuário final)
anos = Counter()
for r in csv.DictReader(open(MONTHLY, encoding="utf-8")):
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
for r in csv.DictReader(open(WEEKDAY_HOUR, encoding="utf-8")):
    d, h = int(r["weekday"]), int(r["hour_brt"])
    grid[d][h] = int(r["revocations"])
    nomes[d] = r["dia"]
fig, ax = plt.subplots(figsize=(4.6, 1.9))
im = ax.imshow(grid, aspect="auto", cmap="Blues")
ax.set_yticks(range(7), nomes)
ax.set_xticks(range(0, 24, 3))
ax.set_xlabel("hora (horário de Brasília)")
fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
fig.tight_layout()
fig.savefig(FIGS / "dia-hora.pdf")

# Números citados no texto
res = json.load(open(MEASURED, encoding="utf-8"))
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
    "JanelaComercial": br(cf["business_hours_mean_h"]),
    "JanelaForaComercial": br(cf["off_hours_mean_h"]),
}
write_macros(macros, "w")
print("\n".join(f"{k} = {v}" for k, v in macros.items()))

# Fronteira de Pareto: consultas × perda esperada por 1.000 ações (cenário medido)
cen = res["scenarios"]["medido"]["rows"]
pts = [(r["fetches_per_1000"], r["expected_loss_per_1000_brl"], r["policy"], r["setting"]) for r in cen]
frente = []
for p in sorted(pts, key=lambda p: (p[0], p[1])):
    if not frente or p[1] < frente[-1][1] - 1e-9:
        frente.append(p)
estilos = {"consultar sempre": ("s", "#333333"), "prazo fixo": ("o", "#4a6fa5"), PROP: ("^", "#c0504d"), "faixas de valor": ("D", "#9bbb59")}
fig, ax = plt.subplots(figsize=(4.6, 2.6))
for pol, (m, c) in estilos.items():
    sel = [p for p in pts if p[2] == pol]
    ax.scatter([p[0] for p in sel], [p[1] for p in sel], marker=m, color=c, s=16, label=pol, zorder=3)
ax.plot([p[0] for p in frente], [p[1] for p in frente], color="#999999", lw=0.8, zorder=2)
ax.set_xscale("log")
ax.set_xlabel("consultas ao status por 1.000 ações")
ax.set_ylabel("perda esperada (R\\$/1.000 ações)")
ax.legend(fontsize=7, frameon=False)
fig.tight_layout()
fig.savefig(FIGS / "pareto.pdf")
prop_frente = [p for p in frente if p[2] == PROP]
fixo12 = next(p for p in pts if p[2] == "prazo fixo" and p[3] == "12 h")
prop001 = next(p for p in pts if p[2] == PROP and p[3] == "L=0.01")
extra = {
    "PerdaPiso": br(pts[0][1], 2),
    "PropConsultas": br(prop001[0], 0),
    "PropPerda": br(prop001[1], 2),
    "FixoDozeConsultas": br(fixo12[0], 0),
    "FixoDozePerda": br(fixo12[1], 2),
    "PropNaFrente": str(len(prop_frente)),
}
write_macros(extra)
print("frente:", [(p[2], p[3], round(p[0]), round(p[1], 2)) for p in frente])
print(extra)

# Desempenho (data/bench.json, cópia de kya-brasil/research/bench/results.json)
bench = json.load(open(BENCH, encoding="utf-8"))
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
    f.write("% Gerado por research/paper/figuras.py a partir de research/bench/results.json; não editar à mão.\n\\newcommand{\\LinhasDesempenho}{%\n")
    for rot, k in linhas:
        d = 0 if med[k]["median_ms"] >= 100 else 1
        f.write(f"{rot} & {ms(k, d)} & {p95(k, d)} \\\\\n")
    f.write("}\n")
extra = {
    "BenchCPU": env["cpu"].replace("(R)", "").replace("  ", " ").strip(),
    "BenchNode": env["node"].lstrip("v"),
    "BenchCore": env["packages"][CORE],
    "LookupSerpro": br(med["crl_serpro_lookup"]["median_ms"] * 1000, 1),
    "TamCredencial": kb(sz["credential_json"]),
    "TamCabecalhos": kb(sz["request_headers_total"]),
    "TamCabecalhosCoass": kb(sz["request_headers_total_1_cosignature"]),
    "TamSerpro": br(sz["crl_serpro"] / 1024 / 1024, 1),
    "OfflineMs": ms("authenticate_offline"),
}
write_macros(extra)
print(extra)

# Compatibilidade das bibliotecas com as LCR reais (data/crl_compat.json, cópia de
# kya-brasil/research/crl-compat/results/results.json)
cc = json.load(open(CRL_COMPAT, encoding="utf-8"))
libs = cc["libraries"]
nomes_lib = {"OpenSSL CLI": "OpenSSL", "Go crypto/x509": "Go \\texttt{crypto/x509}", "Python cryptography": "Python \\texttt{cryptography}",
             "@peculiar/x509": "\\texttt{@peculiar/x509}", PKIJS: "PKI.js", "node-forge": "node-forge", CORE: "Esta biblioteca"}
grupos = ["rsa_small", "rsa_large", "ecdsa_p521", "ecdsa_brainpool", "ed448", "ed521"]
with open(FIGS / "compat.tex", "w", encoding="utf-8") as f:
    f.write("% Gerado por research/paper/figuras.py a partir de research/crl-compat/results/results.json; não editar à mão.\n\\newcommand{\\LinhasCompat}{%\n")
    for lib, nome in nomes_lib.items():
        t = libs[lib]
        ver = t["version"].lstrip("go")
        cel = [f"{t['groups'][g]['ok']}/{t['groups'][g]['n']}" for g in grupos]
        f.write(f"{nome} {ver} & " + " & ".join(cel) + f" & {t['end_entity_ok']}/{t['end_entity_n']} \\\\\n")
    f.write("}\n")
g0 = libs[CORE]["groups"]
extra = {
    "CompatFontes": str(cc["crls"]),
    "CompatFontesTotal": str(cc["crls"] + len(cc["unreachable"])),
    "CompatVerificaveis": str(cc["verifiable"]),
    "CompatLimiar": br(cc["large_threshold"], 0),
    "CompatGrandes": str(g0["rsa_large"]["n"]),
    "CompatUF": str(libs[CORE]["end_entity_n"]),
    "CompatCoreOk": str(libs[CORE]["total_ok"]),
    "CompatOpensslOk": str(libs["OpenSSL CLI"]["total_ok"]),
    "CompatPeculiarUF": str(libs["@peculiar/x509"]["end_entity_ok"]),
    "CompatPkijsUF": str(libs[PKIJS]["end_entity_ok"]),
    "CompatData": cc["fetched_at"][:10],
}
write_macros(extra)
print(extra)

# Sensibilidade: ganho da política proporcional sobre o prazo fixo de mesmo número de consultas
# (data/sensitivity.json, cópia de kya-brasil/research/freshness-sim/sensitivity.json sem as linhas de cada política)
sens = json.load(open(SENSITIVITY, encoding="utf-8"))
fig, ax = plt.subplots(figsize=(4.6, 2.2))
for med, (m, c) in zip(sens["medians_brl"], (("o", "#4a6fa5"), ("^", "#c0504d"))):
    sc = [s for s in sens["scenarios"] if s["median_brl"] == med and s["best"]]
    ax.plot([s["multiplier"] for s in sc], [100 * s["best"]["share_of_avoidable"] for s in sc], marker=m, color=c, ms=4, lw=1,
            label=f"mediana R\\$ {br(med, 0)}")
ax.set_xscale("log")
ax.set_xticks(sens["multipliers"], [f"{k}×" for k in sens["multipliers"]])
ax.set_xlabel("taxa de comprometimento (múltiplo da taxa medida)")
ax.set_ylabel("perda evitável\nremovida (%)")
ax.set_ylim(0, 100)
ax.legend(fontsize=7, frameon=False)
fig.tight_layout()
fig.savefig(FIGS / "sensibilidade.pdf")
pick = {(s["multiplier"], s["median_brl"]): s for s in sens["scenarios"]}
um, cem = pick[(1, 200.0)], pick[(100, 200.0)]
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
write_macros(extra)
print(extra)
