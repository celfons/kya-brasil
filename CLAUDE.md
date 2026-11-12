# CLAUDE.md — kya-brasil

Contexto para sessões de IA. As regras editoriais, as decisões do autor e o calendário da pesquisa moram em
**kya-paper/CLAUDE.md**; leia-o também. Aqui ficam só as regras deste repositório.

## O que é

Monorepo pnpm da biblioteca KYA Brasil (mandatos de agentes de IA assinados com certificado ICP-Brasil) e da
pesquisa que a acompanha.

| Pasta | O quê |
|---|---|
| `packages/core` | A biblioteca: mandato, delegação, emissão, LCR, atualidade, coassinatura. Pura, sem rede. |
| `packages/agent-tools` | Verificador HTTP (`createKyaAuth`), assinatura de requisições, cache de replay, modo offline. |
| `packages/mcp`, `packages/study-kit`, `apps/worker`, `infra` | Servidor MCP, kit do estudo H3, emissor hospedado, infraestrutura. |
| `docs/formal` | Alloy 6: `mandate.als` (H1), `threats.als`, `adversarial.als` (H4), `conformance.als`, `representative.als` (D-43), `timestamp.als` (D-45); geradores; `results-2026-11.txt` (saída literal). |
| `docs/vectors` | Vetores gerados: conformidade (1.320), adversariais (326), certificado (23), representante (140, de `representative.als`), carimbo do tempo (120, de `timestamp.als`). Dois vetores concretos de emissão pelo principal, com cadeia de teste: `self-issued-v1.json` (e-CNPJ, forma de transição) e `self-issued-representative-v1.json` (e-CPF do representante, com a lista de quem verifica). Os testes das bibliotecas os replicam. |
| `research/freshness-sim` | Scripts de medição (`fetch_*.py`), fatores (`fetch_factors.py`), simulações (semente fixa) e `data/`. |
| `research/differential` | A biblioteca contra o OpenSSL nos mesmos bytes: entradas das LCR de um corte, LCR mutadas, assinatura CMS do vetor. Rodar de novo a cada corte e a cada mudança em `crl-der.ts`, `revocation.ts` ou `icp-brasil.ts`. |
| `research/mutation` | Stryker no core, em cinco lotes, no próprio diretório do pacote (restaura os arquivos ao fim; não commitar `packages/core` durante a execução). Sobrevivente em regra pede teste de borda, não mudança na regra. |
| `research/paper/figuras.py` | Cópia pública do gerador de figuras do kya-paper, sincronizada em 7 nov. 2026 (corte teste-2026-11). A cada corte, copiar de novo de `kya-paper/scripts/figuras.py`. |

## Invariantes (não quebrar)

- **Agnóstica quanto ao risco.** Nenhum parâmetro de política tem valor padrão (`max_age_seconds`, L, λ,
  `delegation`, coassinatura). Quem verifica decide; a biblioteca recusa entrada incompleta em vez de assumir.
- **Uma regra, um lugar.** `mandateSubsetProblems` é a única definição de contenção; emissão e verificação a
  chamam. `checkAction` é a única avaliação de ação. `canonicalize` (core, `attestation.ts`) é o único JSON canônico, conforme a RFC 8785; o cliente o importa. O Alloy espelha essas funções, predicado por regra: mudou a
  regra, muda o modelo e regeneram-se os vetores.
- **Falhar fechado.** LCR velha, assinatura que não verifica, algoritmo fora do conjunto, cadeia desconhecida:
  recusa com `KyaError` e código nomeado. Nunca aceitar por omissão.
- **ICP-Brasil depois da Resolução 211/2024** (SPEC seção 22): selo eletrônico (SE-S, SE-H) é recusado como
  assinatura; mandato de empresa assinado só pelo e-CPF do representante só é aceito contra a lista de
  representantes de quem verifica, e sem lista é recusado. Não afrouxar nenhum dos dois. O emissor hospedado não
  emite essa forma (D-46): não tem lista de representantes, e recusa o e-CPF num desafio de empresa dizendo por quê.
- **Carimbo do tempo** (SPEC seção 23): a biblioteca confere o carimbo e devolve a hora atestada; confiar numa
  autoridade e exigir carimbo são de quem verifica, sem padrão. A biblioteca monta o pedido e não fala com a
  autoridade. Carimbo apresentado que não confere é recusado, exigido ou não.
- **Privacidade da coassinatura**: a credencial guarda hash do certificado do e-CPF, nunca o CPF.
- `verifyDelegationChain` também recusa elo expirado, emitido no futuro ou que vive mais que o de cima; o modelo
  não tem tempo nos elos, e o README diz isso.

## Como trabalhar

- `pnpm install --frozen-lockfile`; `pnpm -r typecheck`; `pnpm -r test` (core ~390, agent-tools ~120). O
  TypeScript é estrito (`noUncheckedIndexedAccess`): índice de array pode ser `undefined`.
- Branch `claude/<slug>` a partir de `main`, PR para `main`, squash. O CI roda typecheck, testes, CodeQL e
  **SonarCloud**, que recusa regex com repetição aninhada e código duplicado. Merge autorizado pelo autor.
- **Alloy**: rodar de dentro de `docs/formal` (os `open` resolvem pelo diretório): `java -jar alloy.jar exec -f -o
  out docs/formal/mandate.als`; vetores com `exec -f -r 20 -t xml -o out-adversarial adversarial.als` e
  `python3 -I docs/formal/generate-adversarial.py`. Escopo com `5 Int` sempre que houver tempos 0..10. Toda
  mudança em `.als` atualiza `results-2026-11.txt` (ou um novo arquivo datado) e o README de `docs/formal`.
- **Scripts de pesquisa** (`research/freshness-sim`): ordem `fetch_measured`, `fetch_flow`, `fetch_delays`,
  `fetch_availability`, `fetch_reasons`, `fetch_pix*`, `fetch_factors`; depois `simulate_measured`,
  `simulate_measured_delay`, `simulate_availability`, `scenarios`, `sensitivity`, e por fim `manifest`. Cada simulação
  registra o SHA-256 das entradas que havia em `data/` (`provenance.py`), e `manifest.py` só escreve `manifest.json` se
  as entradas do coletor forem do mesmo corte e os resultados tiverem saído delas; mudou uma entrada, rodam-se de novo
  as simulações. `research/bench` e `research/integration` são medidos no mesmo commit, para saírem da mesma versão
  do core. Precisam de `cryptography >= 50` (versões anteriores
  recusam uma LCR do Serpro); nenhuma LCR é pulada: a que a biblioteca Python não decodifica (hoje só a Certisign
  OM-BR, Ed448) é lida pelo leitor DER de `crl_entries.py`, e, se nenhum dos dois a lê, o corte para.
  `fetch_reasons` lê os mesmos arquivos que `fetch_measured` nomeou; `fetch_measured --reread` refaz a grade de um
  corte a partir deles. A escala da chance de registro por hora em `simulate_measured` é escolha declarada, e
  `staff_scale` dá a janela com metade e com o dobro. `fetch_factors` dá o fator de cima (`factor_max`, só entre listas
  observadas pelo mesmo tempo) e o de baixo (`factor_min`, a fração de comprometimento de chave entre as entradas com
  motivo). As chamadas ao coletor têm 4 tentativas.
- Nome de AC no ITI ≠ id da fonte: `figuras.py` tem `ALIAS_ITI`; fonte nova com grafia diferente entra lá (nas
  duas cópias).
- Releases: `research-AAAA.MM` no GitHub viram versão no Zenodo (DOI conceito 10.5281/zenodo.23973230).
