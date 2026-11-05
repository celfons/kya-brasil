# research/paper

`figuras.py` generates the paper's figures and every number its text cites, from the results the scripts in
`research/` write: `bench/results.json`, `freshness-sim/results_measured.json` and `sensitivity.json`,
`freshness-sim/data/weekday_hour.csv` and `crl-compat/results/results.json`. `data/monthly.csv` is a copy from the
kya-icp dataset (DOI 10.5281/zenodo.23977027, CC BY 4.0).

```bash
python3 -I research/paper/figuras.py   # needs matplotlib; writes out/
```

`out/numeros.tex` holds one LaTeX macro per number in the text (e.g. `\TotalRevog`, `\JanelaMedia`, `\SensUmPct`),
`out/desempenho.tex` and `out/compat.tex` the rows of the two tables, and `out/*.pdf` the figures. This is a public
copy of the paper repository's script, reading this repository's paths.
