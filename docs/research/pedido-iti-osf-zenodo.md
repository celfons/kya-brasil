# Pedido ao ITI, pré-registro no OSF e DOI no Zenodo

## 1. Pedido de acesso à informação ao ITI (fala.br)

**Onde:** https://falabr.cgu.gov.br → entrar com gov.br → "Acesso à informação" → órgão: **ITI – Instituto Nacional de Tecnologia da Informação**.
**Prazo legal:** 20 dias, prorrogáveis por mais 10 (Lei 12.527/2011, art. 11).
**Formato pedido:** CSV ou planilha (art. 8º, §3º, II: formato aberto, legível por máquina).

### Resumo (campo curto)

Certificados ICP-Brasil emitidos, ativos e revogados por autoridade certificadora, por mês, de 2016 a 2026, e motivos de revogação.

### Texto do pedido

> Com base na Lei nº 12.527/2011, solicito, em formato aberto e legível por máquina (CSV ou planilha), os dados agregados abaixo sobre certificados digitais da ICP-Brasil, para fins de pesquisa acadêmica sobre a atualidade da verificação de revogação. Não solicito dado pessoal: apenas contagens agregadas.
>
> 1. Quantidade de certificados de usuário final **emitidos por mês**, de janeiro de 2016 até o mês mais recente disponível, por **autoridade certificadora (AC) emissora**, por **tipo** (A1, A3, outros) e por **titular** (pessoa física, pessoa jurídica, equipamento/aplicação).
> 2. Quantidade de certificados **ativos** (válidos e não revogados) no último dia de cada mês, no mesmo período e com as mesmas divisões.
> 3. Quantidade de certificados **revogados por mês**, no mesmo período, por AC emissora e, quando registrado, por **motivo de revogação** (códigos da RFC 5280: keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, unspecified, entre outros) ou pela classificação equivalente usada pelo ITI ou pelas ACs.
> 4. Se o ITI dispuser: o **tempo médio entre o pedido de revogação e a sua inclusão na lista de certificados revogados (LCR)**, por AC, ou a norma ou relatório de auditoria que trate desse prazo.
> 5. A descrição da fonte e da metodologia dos números publicados em https://numeros.iti.gov.br (por exemplo, o campo "cerVisGerAtivos" e a data de "finalizado"), e se há série histórica desse painel.
>
> Caso alguma divisão não esteja disponível, peço que os demais itens sejam atendidos com o nível de detalhe existente (art. 7º, §2º), e que seja indicado qual informação não existe ou onde ela pode ser obtida (art. 11, §1º, III). Se o ITI não detiver os dados por AC, peço a indicação do órgão ou das entidades que os detêm.

**Depois de protocolar:** anote o número do protocolo (NUP). Se a resposta vier incompleta, você pode entrar com recurso em 10 dias (art. 15).

---

### Resultado

- Protocolos: **00137.011046/2026-56** (5 nov. 2026, prazo 25 nov. 2026) e **00137.011140/2026-13** (6 nov. 2026, prazo
  30 nov. 2026), com o mesmo texto.
- Resposta ao 00137.011046/2026-56: o ITI, como AC Raiz, declara a **inexistência** das bases pedidas (Lei 12.527/2011,
  art. 12, parágrafo único; Decreto 7.724/2012, art. 13, parágrafo único). Emissão, revogação e LCR de usuário final são
  atribuição de cada AC (MP 2.200-2/2001, art. 8º, I, e art. 14), que guarda os dados da própria carteira; o ITI não tem
  base centralizada por titular, tipo, motivo de revogação ou prazo até a LCR. O prazo é auditado pelos DOC-ICP-08
  (auditoria) e DOC-ICP-09 (fiscalização). O painel numeros.iti.gov.br divulga só totais, sem microdados nem série
  histórica estruturada.
- Decisão: não recorrer (a negativa é por inexistência, e o que o recurso poderia render, a série do painel, o coletor
  já guarda desde nov. 2026) e não pedir às AC agora. O artigo cita a resposta: as LCR públicas são a única base comum
  para medir a revogação na ICP-Brasil.
- **Desvio do pré-registro:** o plano previa usar a resposta do ITI como denominador por AC. Como o dado não existe no
  ITI, a taxa usa o total do painel e é tratada como intervalo (de 1 a 100 vezes a medida na análise de sensibilidade).

## 2. Pré-registro no OSF

**Onde:** https://osf.io → criar conta → "Create new project" (título abaixo) → aba "Registrations" → "New registration" → modelo **"OSF Preregistration"**. Antes de registrar, envie o PDF do pré-projeto à aba "Files". Depois de registrado, o conteúdo fica congelado, com data e DOI do OSF. O registro pode ficar sob embargo por até 4 anos.

**Título do projeto:** KYA Brasil: emissão e verificação de mandatos de agentes de inteligência artificial com certificado ICP-Brasil

### Respostas para os campos do modelo

**Study information — Hypotheses**

- H1: A biblioteca do KYA Brasil emite e verifica mandatos de forma equivalente ao modelo formal em Alloy: nenhum contraexemplo para as propriedades de não ampliação de poderes na delegação, cascata da revogação, equivalência entre emissão e verificação, proteção contra *replay* com memória até a expiração da requisição, e vontade da empresa só com coassinatura de representante listado; e nenhuma divergência entre modelo e biblioteca nos vetores de conformidade.
- H2: A política de atualidade proporcional ao valor (idade máxima do status = L / (valor × λ)) fica na fronteira de Pareto entre perda esperada e número de consultas ao status, quando comparada a prazos fixos (consultar sempre, 6 h, 24 h) e a faixas de valor, sob os parâmetros medidos nas LCR da ICP-Brasil.
- H3: Integradores independentes conseguem verificar um mandato só pela documentação, sem alterar a biblioteca.

**Design plan**

- Tipo: estudo observacional (coleta de LCR), verificação formal, simulação de Monte Carlo e estudo de caso.
- Cegamento: não se aplica.

**Sampling plan**

- Dados existentes: sim, em parte. A coleta horária das LCR começou em 4 nov. 2026; uma análise exploratória dos dados de 5 nov. 2026 já foi feita e está declarada (ver "Other").
- Coleta: download a cada hora, por 12 meses ou mais, das LCR de usuário final e de AC listadas no repositório público https://github.com/celfons/kya-icp (sources.json), com os arquivos brutos preservados (Cloudflare R2). Denominador: painel público do ITI (numeros.iti.gov.br), guardado a cada nova versão, e a resposta ao pedido de acesso à informação (NUP a informar).
- Tamanho da amostra: todas as entradas de todas as LCR coletadas no período; não há amostragem.
- Regra de parada: 12 meses de coleta ou o fim do programa, o que vier primeiro.

**Variables**

- λ (taxa de revogação por certificado por hora), por AC e total = revogações no mês ÷ certificados ativos.
- Atraso de publicação = thisUpdate da primeira LCR coletada que contém a revogação − revocationDate.
- Distribuição por dia da semana e hora (horário de Brasília) das revogações.
- Disponibilidade = proporção das coletas com LCR válida, por fonte.
- Motivo de revogação, quando presente.
- Estudo de caso: tempo até a primeira verificação correta, alterações pedidas à biblioteca, tempo até a revogação valer.

**Analysis plan**

- H1: executar todos os comandos do Alloy 6 (docs/formal) com escopo declarado no repositório; regenerar os vetores de conformidade e rodá-los contra a biblioteca. Critério: nenhum contraexemplo inesperado e nenhuma divergência.
- H2: simulação de Monte Carlo com semente fixa (research/freshness-sim/simulate_measured.py), usando λ, atraso e distribuição horária medidos; comparar as políticas pela perda esperada e pelo número de consultas por 1.000 ações; relatar a fronteira de Pareto e se a política proporcional está nela. Intervalos de confiança de 95% por *bootstrap* sobre os meses de coleta.
- H3: análise qualitativa do diário de integração; critério: integrar sem alterar a biblioteca.
- Dados faltantes: fontes fora do ar entram como indisponibilidade; meses antigos das LCR são tratados como piso, porque as ACs retiram os certificados expirados.

**Other**

Análise exploratória já feita antes deste registro (5 nov. 2026):

- 182.907 revogações em 11 LCR de usuário final, de 2012 a 2026;
- cerca de 3,4 mil revogações por mês em 2026;
- 94% delas em dias úteis, das 8h às 18h;
- λ de cerca de 0,24% ao ano (piso);
- simulação com esses parâmetros: janela de exposição média de 15,5 h (48 h a partir de sexta às 19h);
- os comandos do Alloy listados em docs/formal/README.md.

As hipóteses acima foram escritas antes dos 12 meses de coleta, que são a base dos testes confirmatórios.

---

## 3. DOI no Zenodo (código e dados)

Os repositórios já têm `CITATION.cff` e `.zenodo.json` (PRs celfons/kya-brasil#32 e celfons/kya-icp#8).

1. Em https://zenodo.org, entre com a conta do GitHub ("Log in with GitHub").
2. Menu do usuário → **GitHub** → ative a chave de **celfons/kya-brasil** e de **celfons/kya-icp**.
3. Em cada repositório, crie uma release no GitHub. Sugestão: `v2026.11.05` no kya-icp e `research-2026.11.05` no kya-brasil. O Zenodo arquiva o código da release e gera o DOI em poucos minutos.
4. Copie o DOI ("Concept DOI", que vale para todas as versões) e coloque no README, no OSF ("Files" → link) e no pré-projeto, nas referências.

**Dados do R2:** a release do kya-icp guarda o código, não os dados. Para arquivar os dados, baixe os CSV e envie-os como um registro "Dataset" separado no Zenodo ("New upload"):

- https://kya-icp-collector.marcelfons.workers.dev/api/monthly.csv
- https://kya-icp-collector.marcelfons.workers.dev/api/weekday-hour.csv
- https://kya-icp-collector.marcelfons.workers.dev/api/iti.csv

Também vale enviar `research/freshness-sim/data/` e `results_measured.json`. Repita o envio quando houver mais meses de coleta; o Zenodo versiona.
