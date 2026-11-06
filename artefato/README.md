# KYA Brasil: artefato do artigo

Artefato do artigo *Mandatos de agentes de IA com certificado ICP-Brasil: desenho, verificação formal e medição
da revogação* (SBSeg).

**Resumo do artigo.** Agentes de IA já compram, fazem pedidos e pagam em nome de pessoas e empresas, mas quem
recebe a ação não sabe quem responde pelo agente nem até onde ele pode agir. O titular de um certificado ICP-Brasil
(e-CNPJ ou e-CPF) emite um mandato assinado para o agente, e qualquer sistema o verifica sem consultar serviços no
momento da ação. Um modelo em Alloy da emissão, da delegação e do modelo de ameaças encontrou duas falhas,
corrigidas e depois provadas; 1.320 vetores de conformidade ligam o modelo à biblioteca. Medimos a revogação de
certificados de usuário final da ICP-Brasil com dados públicos e usamos a medição para calibrar por quanto tempo o
verificador pode confiar numa prova de status. Testamos também se as bibliotecas X.509 usuais conseguem verificar as
LCR que a ICP-Brasil de fato publica.

O artefato é este repositório (biblioteca `@kya-brasil/core` e os scripts de avaliação em `research/` e
`docs/formal/`), com os dados abertos do coletor de LCR ([kya-icp](https://github.com/celfons/kya-icp),
DOI 10.5281/zenodo.24011370).

# Estrutura do readme.md

Selos considerados; informações básicas; dependências; preocupações com segurança; instalação; teste mínimo;
experimentos (uma seção por reivindicação do artigo); licença.

# Selos Considerados

Os selos considerados são: Disponíveis (SeloD), Funcionais (SeloF), Sustentáveis (SeloS) e Reprodutíveis (SeloR).

# Informações básicas

- Sistema: Linux x86-64 (testado em Ubuntu 24.04 e no executor `ubuntu-latest` do GitHub Actions). macOS deve
  funcionar; Windows não foi testado.
- Hardware: 4 vCPUs e 4 GB de RAM bastam; os números do artigo foram medidos num Intel Xeon 2,1 GHz com 4 vCPUs.
  Disco: cerca de 1 GB, quase todo de `node_modules` (644 MB).
- Rede: a instalação baixa pacotes do npm; as reivindicações R3 e, opcionalmente, R4 baixam LCR públicas dos
  servidores das AC e do coletor kya-icp. R1, R2 e R5 rodam sem rede depois da instalação.

| Pasta | O que tem |
|---|---|
| `packages/core` | a biblioteca (TypeScript, sem rede, sem estado) e os seus testes |
| `docs/formal` | modelos Alloy 6 (`mandate.als`, `conformance.als`, `threats.als`) e o gerador dos vetores |
| `docs/vectors` | vetores de conformidade (1.320) e de teste |
| `research/bench` | desempenho (tabela de tempos) |
| `research/crl-compat` | LCR reais em sete bibliotecas X.509 (tabela de compatibilidade) |
| `research/freshness-sim` | janela de exposição, políticas de atualidade e sensibilidade |
| `research/paper` | `figuras.py`: as figuras e todos os números citados no texto, a partir dos resultados acima |

# Dependências

- Node.js 22 (testado com 22.23.4) e pnpm 10 (testado com 10.28.0). As versões das bibliotecas estão fixadas em
  `pnpm-lock.yaml`.
- Python 3.11 ou mais novo, com `numpy` (R4, R5) e `cryptography` (R3; testado com 50.0.1).
- OpenSSL 3 (R3; testado com 3.0.13) e Go 1.24 (R3; testado com 1.24.7).
- Opcional, para refazer a verificação formal (R1b): Java 17 e o Alloy 6.2.0 (`org.alloytools.alloy.dist.jar`, de
  https://github.com/AlloyTools/org.alloytools.alloy/releases).

# Preocupações com segurança

Nenhuma reivindicação usa certificado ou chave reais. Os testes e o benchmark criam uma infraestrutura de chaves
descartável (`examples/quickstart/make-test-pki.mjs`), marcada como TEST ONLY. R3 baixa LCR e certificados de AC
públicos, por HTTP, dos repositórios das AC e do ITI, e só os lê como dados (nada baixado é executado). Nenhum
script pede privilégio de administrador, abre porta ou escreve fora do repositório.

# Instalação

```bash
git clone https://github.com/celfons/kya-brasil && cd kya-brasil
corepack enable && pnpm install --frozen-lockfile
python3 -m pip install numpy cryptography
```

# Teste mínimo

```bash
pnpm --filter @kya-brasil/core test
```

Resultado esperado em cerca de 30 s: todos os testes passam (123 na versão 0.19.2), entre eles
`conformance.test.ts` (os 1.320 vetores) e `icp-raiz-crls.test.ts` (LCR reais da AC Raiz v3, v4, v6 e v7).

# Experimentos

## Reivindicação R1: emissão e verificação concordam com o modelo formal (seção "Verificação formal" do artigo, H1)

```bash
pnpm --filter @kya-brasil/core test
```

Cerca de 30 s, 1 GB de RAM. Esperado: os 1.320 vetores gerados pelo Alloy passam (`conformance.test.ts`).

R1b (opcional, Java): refazer os comandos Alloy e os vetores, como em `docs/formal/README.md`:

```bash
java -jar org.alloytools.alloy.dist.jar exec -f -o out-checks docs/formal/mandate.als
java -jar org.alloytools.alloy.dist.jar exec -f -o out-threats docs/formal/threats.als
```

Esperado: os resultados das tabelas de `docs/formal/README.md` e da tabela do modelo de ameaças do artigo (nenhum contraexemplo nas
propriedades provadas; contraexemplos nas que o artigo diz que falham sem a defesa).

## Reivindicação R2: tempos e tamanhos (seção "Desempenho e compatibilidade", tabela de tempos)

```bash
pnpm --filter @kya-brasil/research-bench bench
```

Esperado: `research/bench/RESULTS.md` e `results.json` com a mediana e o p95 de cada operação. Os tempos dependem
da máquina; compare a ordem de grandeza e a relação entre as operações (por exemplo, a verificação offline completa
em dezenas de milissegundos e a LCR do SERPRO em cerca de 0,1 s). Para uma passada curta:
`pnpm --filter @kya-brasil/research-bench bench:smoke`.

## Reivindicação R3: compatibilidade das bibliotecas com as LCR reais (seção "Desempenho e compatibilidade", tabela de LCR por biblioteca)

```bash
pnpm --filter @kya-brasil/research-crl-compat all
```

Precisa de rede, OpenSSL, Go e Python com `cryptography`; cerca de 5 minutos. O módulo `go-e521` baixa o pacote
Go `github.com/pedroalbanese/e521` (com `golang.org/x/crypto`), só aritmética, sem rede nem arquivos. Esperado:
`research/crl-compat/results/RESULTS.md` com a tabela por biblioteca. As LCR mudam a cada poucas horas e um
servidor de AC pode não responder; as contagens podem variar em uma ou duas listas, mas as conclusões não: as
bibliotecas baseadas no asn1js (`@peculiar/x509`, PKI.js) recusam as LCR com mais de cerca de 1.240 entradas, a
node-forge não lê LCR, e nenhuma das sete bibliotecas verifica a LCR da AC Raiz v7 (Ed521). O pacote `e521` também
a recusa, e a forma com o hash completo a verifica (`cd research/crl-compat/go-e521 && go test ./...`).

## Reivindicação R4: janela de exposição e comparação de políticas (seção "Atualidade do status", fronteira de Pareto)

```bash
python3 -I research/freshness-sim/simulate_measured.py
```

Sem rede (lê `research/freshness-sim/data/`), cerca de 5 minutos, semente fixa. Esperado:
`results_measured.json` igual ao do repositório (janela média, mediana e p95, a fronteira de Pareto). Para
refazer `data/` a partir do coletor: `python3 -I research/freshness-sim/fetch_measured.py` (rede). Os números da
medição (seção "Medição da revogação") vêm do conjunto de dados DOI 10.5281/zenodo.24011370.

## Reivindicação R5: sensibilidade das políticas à taxa e ao valor (seção "Atualidade do status", figura de sensibilidade)

```bash
python3 -I research/freshness-sim/sensitivity.py
python3 -I research/freshness-sim/scenarios.py
```

Sem rede, semente fixa, cerca de 15 minutos em 4 vCPUs. Esperado: `sensitivity.json` e `scenarios.json` iguais aos do
repositório: o ganho da política proporcional sobre o prazo fixo de mesmo número de consultas, de 1 a 100 vezes a taxa
medida, nas escalas do Pix B2B e P2B; e a tabela de robustez (dispersão, ações por hora e escala do valor). A escala
do valor vem de `data/pix_cnae.json` e `data/pix.json`; para refazê-los (rede):
`python3 -I research/freshness-sim/fetch_pix_cnae.py` e `python3 -I research/freshness-sim/fetch_pix.py`.

## Reivindicação R7 (exploratória): atraso medido e disponibilidade das LCR (seção "Atualidade do status", parágrafo "Atraso medido")

```bash
python3 -I research/freshness-sim/simulate_measured_delay.py
python3 -I research/freshness-sim/simulate_availability.py
```

Sem rede (lê `research/freshness-sim/data/delays.json`, `availability.json` e `pix.json`), semente fixa, poucos
minutos. Esperado: `results_measured_delay.json` (atraso até a LCR com mediana de 0,59 h e p95 de 2,63 h em 170
revogações; janela média de 13,8–14,3 h) e `results_availability.json` (recusa de 99% e 46% das ações legítimas com
prazos fixos de 15 min e 1 h) iguais aos do repositório. Os dados vão até 6 nov. 2026 (versão 3 do conjunto de dados), e a
reivindicação é exploratória. Para refazê-los a partir do coletor (rede; os números mudam com a coleta):

```bash
python3 -I research/freshness-sim/fetch_delays.py
python3 -I research/freshness-sim/fetch_availability.py
python3 -I research/freshness-sim/fetch_pix.py
```

## Reivindicação R6: os números do texto

```bash
python3 -m pip install matplotlib
python3 -I research/paper/figuras.py
```

Sem rede, segundos. Esperado: `research/paper/out/numeros.tex` com as macros que o artigo cita (por exemplo
`\TotalRevog`, `\JanelaMedia`, `\SensUmPct`, `\CompatCoreOk`) e as figuras em `out/*.pdf`, a partir dos
resultados das reivindicações R2 a R5. Os números do parágrafo exploratório (R7) saem de
`results_measured_delay.json` e `results_availability.json`.

# LICENSE

Código sob a licença MIT (`LICENSE`). Os dados do kya-icp estão sob CC BY 4.0.
