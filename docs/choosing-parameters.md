# Como escolher os parâmetros de risco

A biblioteca não tem valores padrão de risco: quem emite ou verifica um mandato informa cada valor. Esta página
explica cada escolha e dá valores de referência medidos na ICP-Brasil. A infraestrutura também é sua: rode o
verificador e, se quiser, o emissor de referência (`apps/worker`, ver `docs/SELF-HOSTING.md`) onde preferir.

## Ao emitir um mandato (`buildMandate`)

| Campo | O que limita | Como escolher |
| --- | --- | --- |
| `actions` | o que o agente pode fazer | só as ações de que ele precisa; `[]` significa qualquer ação |
| `max_per_operation` | a perda de uma ação indevida | o maior pagamento único que você aceitaria perder |
| `max_per_day` | a perda até alguém perceber | quanto você pode perder num dia; o verificador informa o `spent_today` |
| `counterparties`, `currencies`, `payment_instruments` | para onde o dinheiro pode ir | o mais restrito que o uso permitir; `[]` significa qualquer um |
| `valid_from` / `valid_until`, validade da credencial | quanto tempo um mandato vazado continua utilizável | curta. Uma credencial emitida pelo próprio titular (`urn:kya-brasil:self`) não pode ser revogada sozinha: ela vale até expirar ou até o certificado ser revogado. Se precisar revogar uma credencial isolada antes do prazo, emita-a pelo emissor de referência |
| `delegation` | subagentes | `null`, a menos que precise; nesse caso, o menor `max_depth` e o menor `max_ttl_seconds` |

Os tetos são a única defesa que vale quando a chave do agente é roubada ou o modelo se comporta mal: a atualidade
do status não ajuda nesses casos (`research/freshness-sim`).

## Ao verificar (`freshnessPolicy`)

| Campo | Significado | Referência |
| --- | --- | --- |
| `max_expected_loss` | a perda esperada que você aceita por ação (L) | o seu apetite de risco, na moeda do pagamento |
| `revocation_rate_per_hour.certificate` | λ, com que frequência um certificado é revogado | medido na ICP-Brasil: cerca de 2,8 × 10⁻⁷ por hora (0,24% ao ano). Conta todas as revogações, então é um teto para o comprometimento de chave e um piso de cobertura (`research/freshness-sim`, conjunto de dados DOI 10.5281/zenodo.23985090) |
| `max_age_seconds` | teto para a idade da prova de status, qualquer que seja o valor | a LCR é reemitida a cada 1 a 6 horas; um teto de poucas horas mantém a LCR útil sem buscá-la a cada ação |
| `require` | quais provas são obrigatórias | `["certificate"]` no modo offline; acrescente `"credential"` quando um emissor assina o status |
| `max_clock_skew_seconds` | tolerância entre relógios | alguns minutos |
| `unvalued_action` | ações sem valor | `"refuse"`, ou `"ceiling"` com `action_risk_value` por nome de ação |
| `past_valid_until` | LCR depois do seu `nextUpdate` | `"refuse"` |

A idade permitida é `min(max_age_seconds, L / (valor × λ))`: valores maiores exigem status mais recente. Com o λ
medido, a simulação mostra a regra proporcional na fronteira de Pareto quando há poucas consultas de status.
Qualquer que seja a política, sobra uma janela residual: na ICP-Brasil, a revogação acontece sobretudo em dias
úteis, em horário comercial, e leva em média cerca de 15 horas entre o pedido de revogação e a LCR que o mostra
(`research/freshness-sim/README.md`). Validades curtas e tetos baixos são o que cobre essa janela.

## Verificações opcionais

- **Reapresentação (*replay*):** passe `replayCache` para `createKyaAuth`; cada entrada fica guardada até a
  expiração da própria requisição.
- **Vontade da empresa:** exija a coassinatura (`verifyCompanyWill`) e forneça `representatives(cnpj)` a partir de
  uma fonte em que você confie. Os dados abertos do CNPJ mascaram o CPF do sócio (cada máscara corresponde a 1.000
  CPFs válidos), não têm sócios para MEI e EI e não informam alçadas nem assinatura conjunta; servem como filtro,
  não como prova (kya-icp, `analysis/qsa`).
