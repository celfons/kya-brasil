"""Gera as figuras e os números do artigo a partir dos resultados deste repositório.

Cópia pública de kya-paper/scripts/figuras.py. Lê os resultados que os scripts de research/ escrevem e
data/monthly.csv (cópia do conjunto de dados DOI 10.5281/zenodo.24011370), e escreve em out/ as figuras (PDF),
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
write_macros(extra)
print(extra)

# Quadro de sócios: data/qsa.json, cópia de kya-icp/analysis/qsa/results.json (dados abertos do CNPJ, out./2026)
qsa = json.load(open(HERE / "data" / "qsa.json", encoding="utf-8"))
cob = qsa["cobertura"]
todas = cob["TODAS"]["empresas"]
sem_mei_ei = [v for k, v in cob.items() if not k.startswith("_") and k not in ("TODAS", "MEI (2135 + opcao MEI)", "EI nao-MEI (2135)")]
n_sem = sum(v["empresas"] for v in sem_mei_ei)
adm_sem = sum(v["com_PF_qual_admin_dir_pres_socioadm"]["n"] for v in sem_mei_ei)
mei_ei = cob["MEI (2135 + opcao MEI)"]["empresas"] + cob["EI nao-MEI (2135)"]["empresas"]
extra = {
    "QsaAtivas": br(todas / 1e6, 1),
    "QsaCoberturaSemMei": br(100 * adm_sem / n_sem, 1),
    "QsaMeiEiPct": br(100 * mei_ei / todas, 0),
    "QsaLtda": br(cob["LTDA (2062)"]["com_PF_qual_admin_dir_pres_socioadm"]["pct"], 1),
    "QsaEntradaTresMeses": br(qsa["frescor_entrada"]["entrada_ultimos_3_meses"]["pct"], 1),
}
write_macros(extra)
print(extra)

# Cenários de robustez: escala do valor (Pix), dispersão e tráfego (cópia de kya-brasil/research/freshness-sim/scenarios.json
# sem as linhas de cada política)
cen = json.load(open(RESEARCH / "freshness-sim" / "scenarios.json", encoding="utf-8"))
por_nome = {c["name"]: c for c in cen["scenarios"]}
def faixa(vals, d):
    a, b = min(vals), max(vals)
    return br(a, d) if br(a, d) == br(b, d) else f"{br(a, d)}--{br(b, d)}"


def linha(rot, cs):
    m = lambda f, d: faixa([f(c) for c in cs], d)  # noqa: E731
    return (f"{rot} & {m(lambda c: c['median_brl'], 0)} & {m(lambda c: c['floor_brl_per_1000'], 2)} & "
            f"{m(lambda c: c['proportional_L001']['fetches_per_1000'], 0)} & "
            f"{m(lambda c: c['proportional_L001']['expected_loss_per_1000_brl'], 2)} & "
            f"{m(lambda c: c['fixed_12h']['expected_loss_per_1000_brl'], 2)} \\\\")


sig = [por_nome["sigma no limite inferior"], por_nome["sigma 2,0"]]
linhas = [
    linha("Principal (Pix B2B)", [por_nome["principal"]]),
    "\\midrule",
    linha(f"$\\sigma$ de {br(sig[0]['sigma'], 2)} a {br(sig[1]['sigma'], 1)}", sig),
    linha("0,2 ação/h", [por_nome["0,2 ação/h"]]),
    linha("20 ações/h", [por_nome["20 ações/h"]]),
    linha("Pix P2B", [por_nome["Pix P2B"]]),
]
fixo = lambda n: br(por_nome[n]["fixed_12h"]["fetches_per_1000"], 0)  # noqa: E731
with open(FIGS / "cenarios.tex", "w", encoding="utf-8") as f:
    f.write("% Gerado por scripts/figuras.py; não editar à mão.\n\\newcommand{\\LinhasCenarios}{%\n" + "\n".join(linhas) + "}\n")
    f.write(f"\\newcommand{{\\FixoDozeConsultasBaixo}}{{{fixo('0,2 ação/h')}}}\n\\newcommand{{\\FixoDozeConsultasAlto}}{{{fixo('20 ações/h')}}}\n")
pr = por_nome["principal"]
extra = {
    "PixBtoBMedia": br(cen["means_brl"]["B2B"], 0),
    "PixPtoBMedia": br(cen["means_brl"]["P2B"], 0),
    "PixBtoBMediana": br(pr["median_brl"], 0),
    "SigmaInf": br(cen["sigma_lower_bound"], 2),
    "PixMeses": (lambda m: f"{m[0][4:]}/{m[0][:4]} a {m[-1][4:]}/{m[-1][:4]}")(json.load(open(RESEARCH / "freshness-sim" / "data" / "pix_cnae.json", encoding="utf-8"))["months"]),
    "PropNaFrenteMin": str(min(c["proportional_on_front"] for c in cen["scenarios"])),
}
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)

# Motivos das revogações (reasons.json), estabilidade da série de 2026 (monthly.csv), fraude no Pix (pix_fraud.json)
# e perda na cauda do cenário principal (scenarios.json)
mot = json.load(open((RESEARCH / "freshness-sim" / "data") / "reasons.json", encoding="utf-8"))
com_motivo = {k: v for k, v in mot["sources"].items() if v.get("reasons") and set(v["reasons"]) != {"sem motivo"}}
serasa = next(v for v in mot["sources"].values() if "Serasa" in v["ac"])
pct = lambda d: 100 * d["reasons"].get("key_compromise", 0) / (d["entries"] - d["reasons"].get("sem motivo", 0))  # noqa: E731
mensal = {}
with open(MONTHLY, encoding="utf-8") as fm:
    for r in csv.DictReader(fm):
        if r["tipo"] == "usuario-final":
            mensal[r["mes"]] = mensal.get(r["mes"], 0) + int(r["revogacoes"])
m26 = [mensal[k] for k in sorted(mensal) if k.startswith("2026") and k < "2026-11"]
m25 = [mensal[k] for k in sorted(mensal) if k.startswith("2025")]
fr = json.load(open((RESEARCH / "freshness-sim" / "data") / "pix_fraud.json", encoding="utf-8"))["total"]
pr = por_nome["principal"]
linha_pr = lambda pol, st: next(r for r in pr["rows"] if r["policy"] == pol and r["setting"] == st)  # noqa: E731
perda_valor = pr["proportional_L001"]["expected_loss_per_1000_brl"] / (1000 * cen["means_brl"]["B2B"])
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
    "CaudaPropTres": br(linha_pr("proporcional ao valor", "L=0.03")["tail_loss_per_1000_tail_actions_brl"], 0),
    "PropTresConsultas": br(linha_pr("proporcional ao valor", "L=0.03")["fetches_per_1000"], 0),
    "CaudaFixoDoze": br(linha_pr("prazo fixo", "12 h")["tail_loss_per_1000_tail_actions_brl"], 0),
    "CaudaFixoSeis": br(linha_pr("prazo fixo", "6 h")["tail_loss_per_1000_tail_actions_brl"], 0),
    "FixoSeisConsultas": br(linha_pr("prazo fixo", "6 h")["fetches_per_1000"], 0),
    "CaudaPctPerda": br(100 * linha_pr("prazo fixo", "12 h")["tail_share_of_loss"], 0),
}
with open(FIGS / "numeros.tex", "a", encoding="utf-8") as f:
    for k, v in extra.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(extra)
