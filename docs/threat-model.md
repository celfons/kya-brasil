# Cobertura do modelo de ameaças

Esta é a seção 2.1 do pré-projeto ligada ao produto. Para cada ameaça, a tabela diz:

- **Defesa:** o que o produto faz;
- **Evidência:** o que mostra que a defesa funciona;
- **Risco residual:** o que fica em aberto.

Os comandos do Alloy estão em `docs/formal/mandate.als` e `docs/formal/threats.als` (resultados em `docs/formal/README.md`). Os testes estão em `packages/*/src/*.test.ts`; quando um teste é citado pelo título, o texto entre aspas é o título exato do `it(...)`.

**Tipos de evidência:**

- **Alloy:** propriedade sem contraexemplo no escopo declarado; um contraexemplo esperado registra uma limitação.
- **Vetores:** os 1.320 casos de `docs/vectors/mandate-conformance.json`, rodados contra a biblioteca.
- **Testes:** testes unitários e de propriedade.
- **Dados:** medição nas LCR da ICP-Brasil (`research/freshness-sim`; série do coletor `kya-icp`, DOI 10.5281/zenodo.23977027, ver `CITATION.cff`).

## Resumo

| # | Ameaça | Defesa | Evidência | Situação |
|---|---|---|---|---|
| 1 | Roubo da chave do agente | Limites do mandato; validade curta; revogação da credencial; delegação curta | Vetores, testes | Mitigada, risco limitado ao mandato |
| 2 | Comprometimento da chave do responsável | Revogação na LCR; política de atualidade; efeito da revogação por motivo | Alloy, testes, dados | Mitigada, com janela residual medida |
| 3 | Uso do e-CNPJ por quem não representa a empresa | Coassinatura por e-CPF de representante listado | Alloy, testes | Mitigada se o verificador exigir; premissa da lista do QSA |
| 4 | Emissor hospedado comprometido | Prova do principal verificada só contra a ICP-Brasil; emissão pelo próprio titular | Testes, vetores | Mitigada no modo offline |
| 5 | Emissor hospedado indisponível | Modo offline; o modo online falha fechado | Alloy, testes | Mitigada no modo offline |
| 6 | Reapresentação (*replay*) | Janela de validade curta; cache de requisições até a expiração | Alloy, testes | Mitigada se o verificador ativar o cache |
| 7 | Ampliação de poderes por delegação | Mandato delegado tem de ser subconjunto; profundidade e duração limitadas | Alloy, vetores, testes de propriedade | Mitigada |
| 8 | Aceitação de status desatualizado | Idade máxima do status proporcional ao valor; LCR vencida recusada | Alloy, testes, dados, simulação | Limitada, não eliminada |

## Detalhe

### 1. Roubo da chave do agente

- **Defesa:** quem rouba a chave só faz o que o mandato permite:
  - teto por operação e por dia;
  - moedas, contrapartes e meios de pagamento listados (SPEC §5);
  - validade curta da credencial (SPEC §6), limitada pelo `notAfter` do certificado (D-35);
  - revogação imediata da credencial pelo titular, quando há emissor hospedado (SPEC §10);
  - delegações de curta duração (SPEC §17).
- **Evidência:**
  - vetores `Allows*` e `SubsetNo*` (comandos de `docs/vectors/mandate-conformance.json`);
  - `packages/core/src/mandate.test.ts`, `packages/core/src/delegation.test.ts`;
  - `packages/agent-tools/src/offline.test.ts`: "refuses a tampered mandate, a wrong agent key and a missing proof or credential".
- **Risco residual:**
  - **Credencial autoemitida:** não tem revogação individual. Valem só a validade curta e a revogação do certificado (SPEC §20).
  - **Teto diário:** `max_per_day` depende do `spent_today` informado pelo verificador.

### 2. Comprometimento da chave do responsável (e-CNPJ ou e-CPF)

- **Defesa:**
  - o verificador confere a LCR do certificado (`checkRevocation`);
  - a idade máxima da LCR aceita depende do valor da ação (SPEC §18);
  - o efeito da revogação sobre mandatos já emitidos é política do verificador, por motivo da revogação (D-36);
  - uma autorização assinada depois da revogação, ou depois da `invalidityDate`, nunca é mantida.
- **Evidência:**
  - Alloy: `NoStaleRevokedAccepted` (`threats.als`) vale; `Cascade` (`mandate.als`, P3: credencial fora de vigor não permite nada, qualquer que seja a cadeia) vale;
  - testes: `packages/core/src/revocation.test.ts` (LCR; efeito por motivo, D-36: "applies the caller's policy: revoke on compromise or no reason, suspend on hold, keep a later benign replacement" e "never keeps what was signed after the suspected compromise, or without a date to compare") e `packages/core/src/freshness.test.ts`;
  - `packages/agent-tools/src/offline.test.ts`: "refuses untrusted anchors, an expired credential and a revoked certificate".
  - dados medidos: 94% das revogações em dias úteis, das 8h às 18h; janela média de 15,5 h entre o pedido de revogação e a LCR (simulação).
- **Risco residual:**
  - o intervalo entre o comprometimento e o pedido de revogação não é observável;
  - certificados revogados depois da última LCR aceita passam dentro da janela (`NoRevokedAcceptedOffline`, contraexemplo esperado);
  - até o core 0.19.0, `verifyCrl` recusava LCRs com mais de cerca de 1 240 entradas (limite de nós ASN.1 do asn1js), como a da AC SERPRO RFB v5 (~77 000 entradas): o verificador falhava fechado (502) para todo e-CNPJ dessa AC. Corrigido no 0.19.1 (leitor DER próprio, limitado a 64 MiB e 2 000 000 de entradas; teste com LCR de 200 000 entradas); encontrado pelo benchmark (`research/bench`).

### 3. Uso do e-CNPJ por quem não representa a empresa

O caso típico é o contador que guarda o A1 da empresa.

- **Defesa:**
  - coassinatura, com e-CPF, do mesmo texto assinado (`addCosignature`);
  - `verifyCompanyWill` só aceita se o CPF do e-CPF estiver em `representatives(cnpj)`, a lista do verificador (SPEC §21).
- **Evidência:**
  - Alloy (`threats.als`): `IssuanceImpliesCompanyWill` dá contraexemplo sem coassinatura (o problema); `CoSignatureSound` e `NoCoSignatureNoCompanyWill` valem;
  - testes: `packages/core/src/cosign.test.ts` ("refused: the co-signer's CPF is not a representative", "refused: no co-signature" e os demais do bloco "co-signature by a legal representative (section 21)").
- **Risco residual:**
  - lista de representantes desatualizada (`CoSignatureStaleList`);
  - lista sem CPF completo: os dados abertos do CNPJ publicam o CPF do sócio mascarado (6 de 11 dígitos visíveis; os 3 primeiros e os 2 verificadores ocultos), o que deixa 1.000 CPFs válidos por máscara. Com essa fonte o verificador só confere compatibilidade com a máscara e o nome, não monta a lista que `representatives(cnpj)` pede; ela precisa vir de uma fonte com CPF completo ou de uma declaração assinada pela empresa;
  - e-CPF emprestado (`CoSignatureLentECpf`);
  - verificador que não exige a coassinatura: a defesa é opcional.

### 4. Emissor hospedado comprometido

- **Defesa:**
  - o agente apresenta a prova do principal, o texto assinado mais o CMS (SPEC §19), e o verificador confere contra a ICP-Brasil, sem confiar na chave do emissor;
  - ou o titular emite sem emissor nenhum (SPEC §20, `urn:kya-brasil:self`).
- **Evidência:**
  - testes: `packages/core/src/principal-proof.test.ts` ("refuses a credential whose mandate is not the one signed", "refuses a proof for another agent or another issuer") e `packages/core/src/issuance.test.ts` (bloco "issuance: tampering is refused");
  - vetores: `docs/vectors/self-issued-v1.json`;
  - `packages/agent-tools/src/offline.test.ts`: "refuses an issuer it does not list and a credential edited after the issuer signed it".
- **Risco residual:** sem a prova do principal, o modo online confia no emissor.

### 5. Emissor hospedado indisponível

- **Defesa:**
  - no modo offline (`createKyaAuth({ offline })`), o verificador não chama o emissor;
  - no modo online, a indisponibilidade dá 502 e nada é aceito.
- **Evidência:**
  - Alloy (`threats.als`): `check OfflineIndependentOfIssuer` e `check IssuerDownFailsClosed` valem; `run IssuerDownOfflineStillAccepts` é satisfatível;
  - `packages/agent-tools/src/offline.test.ts`, com `fetch` simulado e verificado como nunca chamado: "accepts the request with no call to fetch and evaluates the mandate locally" e "accepts it with the issuer's public key and the proof, without calling the issuer".
- **Risco residual:** a disponibilidade da própria LCR, que é medida pelo coletor (`kya-icp`).

### 6. Reapresentação (*replay*) de requisições

- **Defesa:**
  - requisição assinada com `created` e `expires`, validade de no máximo 600 s (SPEC §14);
  - `replayCache` guarda o SHA-256 do texto assinado até a expiração da própria requisição e recusa a repetição com `401 KYA_REQUEST_REPLAYED`.
- **Evidência:**
  - Alloy (`threats.als`): `NoReplayToday` dá contraexemplo sem cache; `NoReplayImplemented` vale; `NoReplayShortMemory` e `NoReplayClockDrift` mostram por que a memória dura até a expiração e usa o relógio do verificador;
  - `packages/agent-tools/src/auth.test.ts`, bloco "replay cache (opt-in)": "refuses the same signed request twice, accepts different requests, and nothing changes without the option", "keeps entries until the request expires, then evicts them", "fails closed when full or when the store errors, and needs a bounded lifetime";
  - `packages/agent-tools/src/offline.test.ts`: "refuses a replayed request at the verifier's clock; past its expiry the window refuses it";
  - `examples/quickstart/agent-and-verifier-offline.mjs` (roda no CI).
- **Risco residual:** a defesa só vale com o cache ativado; sem ele, a janela de 600 s fica aberta.

### 7. Ampliação de poderes por delegação

- **Defesa:**
  - cada mandato delegado tem de ser subconjunto do mandato acima: tetos, moedas, contrapartes e ações;
  - profundidade e duração limitadas;
  - só delega quem tem permissão (SPEC §17, D-37).
- **Evidência:**
  - Alloy (`mandate.als`): `NonAmplification`, `ChainNonAmplification`, `IssuedChainNonAmplification` e `NoPermissionNoIssue`;
  - vetores de conformidade (`SubsetNo*`, `IssueBroader`, `IssueNoPermission`);
  - testes de propriedade P1–P4 em `packages/core/src/properties.test.ts` (P1 "non-amplification" é o que trata de delegação);
  - mutações registradas na seção "Mutation checks" de `docs/formal/README.md`.
- **Risco residual:** a duração mínima de 60 s não é exigida na verificação da cadeia; a emissão é mais estrita.

### 8. Aceitação de status desatualizado

- **Defesa:**
  - idade máxima do status de L / (valor × λ), com teto (SPEC §18);
  - recusa de LCR vencida (`pastNextUpdate: "refuse"`), de prova ausente, de relógio inválido e de prova com data futura.
- **Evidência:**
  - Alloy (`threats.als`): `NoStaleRevokedAccepted` vale; `NoStaleRevokedWithoutPolicy` dá contraexemplo sem a política;
  - `packages/core/src/freshness.test.ts`: "refuses missing evidence for a required kind", "refuses evidence dated in the future beyond the caller's clock skew, and accepts it within", "fails closed on another currency, a bad amount or a missing or bad clock" e "turns a CRL lookup into certificate evidence; past nextUpdate it is refused or judged by age, as the caller chose";
  - dados: λ medido de cerca de 0,24% ao ano;
  - simulação: fronteira de Pareto (`research/freshness-sim`), a testar como H2 no pré-registro (osf.io/t59kv).
- **Risco residual:** a política limita a exposição, não a elimina; λ é piso e o motivo da revogação raramente é publicado. Uma LCR que o verificador não consegue ler leva à recusa (falha fechada), não à aceitação de status velho; até o core 0.19.0 isso acontecia com toda LCR grande (ver ameaça 2).

## Fora do escopo

- Comprometimento de uma autoridade certificadora ou da raiz da ICP-Brasil.
- Validade jurídica do mandato: vai para a análise jurídica do pré-projeto.
- Contestação de um ato já praticado pelo agente: o emissor não registra atos (D-19).
