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
| `docs/formal` | Alloy 6: `mandate.als` (H1), `threats.als`, `adversarial.als` (H4), `conformance.als`, `representative.als` (D-43); geradores; `results-2026-11.txt` (saída literal). |
| `docs/vectors` | Vetores gerados: conformidade (1.320), adversariais (326), certificado (23), representante (140, de `representative.als`). Os testes das bibliotecas os replicam. |
| `research/freshness-sim` | Scripts de medição (`fetch_*.py`), fatores (`fetch_factors.py`), simulações (semente fixa) e `data/`. |
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
  representantes de quem verifica, e sem lista é recusado. Não afrouxar nenhum dos dois.
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
  `simulate_measured_delay`, `scenarios`, `sensitivity`. Precisam de `cryptography >= 50` (versões anteriores
  recusam uma LCR do Serpro); `fetch_measured` pula LCR que a biblioteca Python não decodifica (hoje só a Certisign
  OM-BR, Ed448) e avisa. As chamadas ao coletor têm 4 tentativas.
- Nome de AC no ITI ≠ id da fonte: `figuras.py` tem `ALIAS_ITI`; fonte nova com grafia diferente entra lá (nas
  duas cópias).
- Releases: `research-AAAA.MM` no GitHub viram versão no Zenodo (DOI conceito 10.5281/zenodo.23973230).
