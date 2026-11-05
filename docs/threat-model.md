# Cobertura do modelo de ameaças

Esta é a seção 2.1 do pré-projeto ligada ao produto. Para cada ameaça, a tabela diz:

- **Defesa:** o que o produto faz;
- **Evidência:** o que mostra que a defesa funciona;
- **Risco residual:** o que fica em aberto.

Os comandos do Alloy estão em `docs/formal/` (resultados em `docs/formal/README.md`). Os testes estão em `packages/*/src/*.test.ts`.

**Tipos de evidência:**

- **Alloy:** propriedade sem contraexemplo no escopo declarado; um contraexemplo esperado registra uma limitação.
- **Vetores:** os 1.320 casos de `docs/vectors/mandate-conformance.json`, rodados contra a biblioteca.
- **Testes:** testes unitários e de propriedade.
- **Dados:** medição nas LCR da ICP-Brasil (`research/freshness-sim`, DOI 10.5281/zenodo.23977027).

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
  - vetores `Allows*` e `SubsetNo*` (conformidade);
  - `mandate.test.ts`, `delegation.test.ts`;
  - teste de "chave de agente errada" em `offline.test.ts`.
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
  - Alloy: `NoStaleRevokedAccepted` vale e `Cascade` vale;
  - testes: `revocation.test.ts` e `freshness.test.ts`;
  - teste de certificado revogado em `offline.test.ts`.
  - dados medidos: 94% das revogações em dias úteis, das 8h às 18h; janela média de 15,5 h entre o pedido de revogação e a LCR (simulação).
- **Risco residual:**
  - o intervalo entre o comprometimento e o pedido de revogação não é observável;
  - certificados revogados depois da última LCR aceita passam dentro da janela (`NoRevokedAcceptedOffline`, contraexemplo esperado).

### 3. Uso do e-CNPJ por quem não representa a empresa

O caso típico é o contador que guarda o A1 da empresa.

- **Defesa:**
  - coassinatura, com e-CPF, do mesmo texto assinado (`addCosignature`);
  - `verifyCompanyWill` só aceita se o CPF do e-CPF estiver em `representatives(cnpj)`, a lista do verificador (SPEC §21).
- **Evidência:**
  - Alloy: `IssuanceImpliesCompanyWill` dá contraexemplo sem coassinatura (o problema); `CoSignatureSound` e `NoCoSignatureNoCompanyWill` valem;
  - testes: `cosign.test.ts`.
- **Risco residual:**
  - lista de representantes desatualizada (`CoSignatureStaleList`);
  - e-CPF emprestado (`CoSignatureLentECpf`);
  - verificador que não exige a coassinatura: a defesa é opcional.

### 4. Emissor hospedado comprometido

- **Defesa:**
  - o agente apresenta a prova do principal, o texto assinado mais o CMS (SPEC §19), e o verificador confere contra a ICP-Brasil, sem confiar na chave do emissor;
  - ou o titular emite sem emissor nenhum (SPEC §20, `urn:kya-brasil:self`).
- **Evidência:**
  - testes: `principal-proof.test.ts` e `issuance.test.ts` (recusa de mandato, agente, emissor ou validade alterados);
  - vetores: `docs/vectors/self-issued-v1.json`;
  - teste de "credencial do emissor editada após a atestação" em `offline.test.ts`.
- **Risco residual:** sem a prova do principal, o modo online confia no emissor.

### 5. Emissor hospedado indisponível

- **Defesa:**
  - no modo offline (`createKyaAuth({ offline })`), o verificador não chama o emissor;
  - no modo online, a indisponibilidade dá 502 e nada é aceito.
- **Evidência:**
  - Alloy: `OfflineIndependentOfIssuer`, `IssuerDownFailsClosed` e `IssuerDownOfflineStillAccepts`;
  - testes: `offline.test.ts`, com `fetch` simulado e verificado como nunca chamado.
- **Risco residual:** a disponibilidade da própria LCR, que é medida pelo coletor (`kya-icp`).

### 6. Reapresentação (*replay*) de requisições

- **Defesa:**
  - requisição assinada com `created` e `expires`, validade de no máximo 600 s (SPEC §14);
  - `replayCache` guarda o SHA-256 do texto assinado até a expiração da própria requisição e recusa a repetição com `401 KYA_REQUEST_REPLAYED`.
- **Evidência:**
  - Alloy: `NoReplayToday` dá contraexemplo sem cache; `NoReplayImplemented` vale; `NoReplayShortMemory` e `NoReplayClockDrift` mostram por que a memória dura até a expiração e usa o relógio do verificador;
  - testes: `auth.test.ts` e `offline.test.ts`.
- **Risco residual:** a defesa só vale com o cache ativado; sem ele, a janela de 600 s fica aberta.

### 7. Ampliação de poderes por delegação

- **Defesa:**
  - cada mandato delegado tem de ser subconjunto do mandato acima: tetos, moedas, contrapartes e ações;
  - profundidade e duração limitadas;
  - só delega quem tem permissão (SPEC §17, D-37).
- **Evidência:**
  - Alloy: `NonAmplification`, `ChainNonAmplification`, `IssuedChainNonAmplification` e `NoPermissionNoIssue`;
  - vetores de conformidade;
  - testes de propriedade P1–P4;
  - testes de mutação em `docs/formal/README.md`.
- **Risco residual:** a duração mínima de 60 s não é exigida na verificação da cadeia; a emissão é mais estrita.

### 8. Aceitação de status desatualizado

- **Defesa:**
  - idade máxima do status de L / (valor × λ), com teto (SPEC §18);
  - recusa de LCR vencida (`pastNextUpdate: "refuse"`), de prova ausente, de relógio inválido e de prova com data futura.
- **Evidência:**
  - Alloy: `NoStaleRevokedAccepted` vale; `NoStaleRevokedWithoutPolicy` dá contraexemplo sem a política;
  - testes: `freshness.test.ts`;
  - dados: λ medido de cerca de 0,24% ao ano;
  - simulação: fronteira de Pareto (`research/freshness-sim`), a testar como H2 no pré-registro (osf.io/t59kv).
- **Risco residual:** a política limita a exposição, não a elimina; λ é piso e o motivo da revogação raramente é publicado.

## Fora do escopo

- Comprometimento de uma autoridade certificadora ou da raiz da ICP-Brasil.
- Validade jurídica do mandato: vai para a análise jurídica do pré-projeto.
- Contestação de um ato já praticado pelo agente: o emissor não registra atos (D-19).
