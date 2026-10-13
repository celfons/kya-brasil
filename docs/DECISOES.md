# Decisões

| # | Decisão | Motivo |
| --- | --- | --- |
| D-01 | Repositório e Worker separados do KYB Brasil; código pode ser duplicado. | Produtos diferentes, responsabilidade segregada. O KYB não sabe que o KYA existe. |
| D-02 | KYB chamado por Service Binding (`KYB`) no canal `/internal/v1/*` com `KYB_INTERNAL_KEY`. | Chamada Worker a Worker sem HTTP público e sem x402; o preço da credencial já cobre a consulta. Local: `KYB_URL`. |
| D-03 | Prova de vínculo na fase 1 = e-CNPJ (ICP-Brasil), CMS/PKCS#7 destacado sobre o texto do desafio. gov.br na fase 2. | Toda empresa tem e-CNPJ; a assinatura prova posse sem intermediário. |
| D-04 | Chaves de agente: carteira EVM (EIP-191) e Web Bot Auth (Ed25519, RFC 9421). | Cobre agentes que pagam com x402 e agentes HTTP que assinam requisições. |
| D-05 | Mandato = JSON livre validado por esquema público; só os campos reservados são avaliados em `/allowed`; os demais são listados em `not_evaluated`. | Flexível sem prometer o que não se verifica. |
| D-06 | Credencial assinada com Ed25519 (mesmo esquema de atestado do KYB), chaves aposentadas publicadas em `/.well-known/kya.json`. | Verificação offline e estável após rotação. |
| D-07 | Verificação grátis até 50/dia por IP; `/verified` e `/allowed` a 0,01 sem limite; registro 0,50; renovação 0,10; prova e revogação grátis. | Verificar tem de ser barato para o verificador; quem paga é quem emite. |
| D-08 | Sem âncoras ICP-Brasil em KV, nenhuma emissão (fail closed). | Uma cadeia não validada seria uma credencial falsa com assinatura verdadeira. |
| D-09 | Revisão diária por cron: suspende quem deixou de passar no KYB, reativa quem voltou a passar. A assinatura cobre a credencial como emitida; o estado vivo está em `verify_url` e `/v1/revocations`. | Evita reassinar a cada mudança e mantém o histórico auditável. |
| D-10 | Nenhum CPF armazenado ou exposto; o assinante do e-CNPJ fica registrado só pelo hash do certificado. | Mesma regra do KYB Brasil. |
| D-11 | ERC-8004 só na fase 2. | Primeiro provar demanda com credencial fora da cadeia. |
| D-12 | Fase 2, ERC-8004 só leitura: o agente registrado na cadeia é identificado por `eip155:<chain>:<registry>:<agentId>` e assina com o `agentWallet` lido na cadeia; nada é escrito on-chain. | Sem custo de gás nem carteira operacional; a credencial segue off-chain e verificável. Escrita (validações on-chain) fica para quando houver demanda. |
