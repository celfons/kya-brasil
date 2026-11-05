/**
 * Participant-facing texts, in Brazilian Portuguese (the participants are Brazilian developers). Code comments and
 * the package docs stay in English, like the rest of the repository.
 */
import { SCENARIO } from "./policy.js";
import { COMPANY_CNPJ } from "./pki.js";

const fmtCnpj = (c: string) => `${c.slice(0, 2)}.${c.slice(2, 5)}.${c.slice(5, 8)}/${c.slice(8, 12)}-${c.slice(12)}`;
const DOCS = "https://github.com/celfons/kya-brasil";

export const CONSENT = `
==================================================================================
 Estudo de caso KYA Brasil: termo de consentimento
==================================================================================

Você vai integrar a biblioteca KYA Brasil usando apenas a documentação pública,
em quatro tarefas curtas, e responder cinco perguntas abertas no fim.

O QUE O KIT REGISTRA (somente nesta pasta, no seu computador):
  - horários de início e de cada verificação (para medir tempo até concluir);
  - resultado de cada tarefa (passou/falhou) e a categoria do erro
    (assinatura, cadeia ICP, mandato, revogação, validade, repetição, execução, outro);
  - a avaliação da política do mandato que você emitir (quais campos ficaram
    mais permissivos ou mais restritivos que o cenário);
  - quantas linhas e quantos arquivos do seu projeto mudaram (só os números);
  - o tempo que as suas funções de verificação levaram (latência, em ms);
  - suas respostas às perguntas abertas.

O QUE O KIT NÃO REGISTRA:
  - o conteúdo do seu código;
  - nome, e-mail, usuário, caminho de pastas, nome da máquina ou outro
    identificador do computador;
  - nada da sua rede: o kit não faz nenhuma conexão de rede.

Você recebe um identificador anônimo aleatório. Nada sai do seu computador até
você mesmo enviar o arquivo de relatório (kya-study report) ao pesquisador; você
pode abrir e ler o arquivo antes de enviar.

Você pode desistir a qualquer momento, sem dar motivo: basta não enviar o
relatório e apagar a pasta.

Para participar, digite exatamente: aceito
`;

export const CONSENT_PROMPT = "Digite \"aceito\" para continuar (ou qualquer outra coisa para sair): ";

export const tasksMd = (p: { agentId: string }) => `# Estudo de caso KYA Brasil: tarefas

> Material de pesquisa. Os certificados em \`pki/\` são de **TESTE, SEM VALOR**: foram gerados agora pelo kit
> e nenhum verificador real confia neles.

## Cenário

A empresa **ACME LTDA TESTE** (CNPJ ${fmtCnpj(COMPANY_CNPJ)}) quer que um agente de IA compre material de
escritório para ela. A política decidida pela diretoria é:

> **O agente pode comprar material de escritório do fornecedor X, até R$ ${SCENARIO.maxPerOperation} por compra
> e R$ ${SCENARIO.maxPerDay.toLocaleString("pt-BR")} por dia, por ${SCENARIO.validityDays} dias, sem delegar a outros agentes.**

- Fornecedor X: **Papelaria Exemplo Ltda**, CNPJ **${fmtCnpj(SCENARIO.supplierCnpj)}**.
- No marketplace onde o agente compra, a ação de compra se chama **\`"${SCENARIO.action}"\`** e os valores são em **BRL**.
- O agente já tem uma chave: \`pki/agente.json\` (endereço \`${p.agentId}\`).
- O e-CNPJ A1 de teste da empresa está em \`pki/empresa.pfx\` (senha em \`pki/pki.json\`); as âncoras de
  confiança de teste em \`pki/anchors.pem\`; a LCR (CRL) da AC de teste em \`pki/ac.crl\`.

## Regras

- Use **somente a documentação**: o [README (seção "Start here")](${DOCS}#start-here), os READMEs de
  [\`@kya-brasil/core\`](${DOCS}/tree/main/packages/core) e [\`@kya-brasil/agent-tools\`](${DOCS}/tree/main/packages/agent-tools),
  o [guia de parâmetros](${DOCS}/blob/main/docs/choosing-parameters.md) e os [exemplos](${DOCS}/tree/main/examples/quickstart).
  Se consultar outras fontes (busca na web, assistentes de IA), conte na última pergunta do fim.
- **Não altere a biblioteca** (arquivos em \`node_modules/@kya-brasil\`). Se você sentir que precisa, anote:
  vamos perguntar no fim.
- Implemente as funções em \`src/emitir.mjs\` e \`src/verificar.mjs\`. Você pode criar outros arquivos em \`src/\`.
- Depois de cada mudança rode \`npx kya-study check\` (todas as tarefas) ou \`npx kya-study check t1\` (uma só).
  Rodar o check muitas vezes é normal e esperado.
- Quando terminar (ou quando decidir parar): \`npx kya-study finish\` e depois \`npx kya-study report\`.

## T1 · Emitir

Em \`src/emitir.mjs\`, implemente \`emitirCredencial(ctx)\`: monte o mandato do cenário, assine com o e-CNPJ de
teste da empresa (emissão pela própria empresa, sem serviço emissor) e devolva \`{ credential, proof }\`.

\`ctx\` traz: \`pfx\` (bytes de \`pki/empresa.pfx\`), \`senha\`, \`cnpj\`, \`agente\` (\`{ kind: "evm", id }\`),
\`anchors\` (certificados PEM de \`pki/anchors.pem\`) e \`agora\` (um \`Date\`).

O kit confere a credencial como um verificador faria (assinatura, cadeia até as âncoras de teste, mandato,
validade).

## T2 · Política

Não há código novo: o kit compara o mandato que a sua T1 emitiu com a política do cenário e diz se ficou
**correto**, **permissivo demais**, **restritivo demais** ou **inválido**, e quais campos divergiram.

## T3 · Verificar

Você agora é o marketplace. Em \`src/verificar.mjs\`, implemente \`criarVerificador(ctx)\`, que devolve uma função
\`async (request) => ({ aceito, motivo })\`. Ela recebe um \`Request\` (API Fetch) assinado pelo agente, que traz a
credencial e a prova da empresa (verificação **offline**: sem emissor, sem rede), e decide se a compra pode seguir.

O corpo de cada pedido é JSON:

\`\`\`json
{ "pedido": "…", "acao": "${SCENARIO.action}", "valor": 120, "moeda": "BRL", "fornecedor": "${SCENARIO.supplierCnpj}" }
\`\`\`

\`ctx\` traz: \`anchors\` (PEM), \`agora()\` (o relógio do verificador: **use este relógio**, não \`new Date()\`) e
\`buscarCrl(url)\`, que devolve os bytes (DER) da LCR publicada naquela URL (faz o papel do \`fetch\`; o kit não
usa rede).

Em \`motivo\`, ao recusar, devolva o código de erro da biblioteca (por exemplo o \`error\` da autenticação) ou a
regra do mandato que recusou.

O kit envia: uma compra dentro do mandato (deve **aceitar**), uma acima do teto, uma para outro fornecedor
e a mesma requisição repetida (devem ser **recusadas**).

## T4 · Revogação

O certificado e-CNPJ da empresa vazou e foi **revogado**: a AC publica uma LCR nova que o lista. O kit cria um
verificador com a sua \`criarVerificador\`, envia uma compra válida (deve ser aceita), publica a LCR nova em
\`buscarCrl\`, avança o relógio \`agora()\` para depois do \`nextUpdate\` da LCR antiga e envia outra compra: ela
deve ser **recusada por revogação** (\`motivo\` com o código de erro de revogação). O kit mede quanto tempo passa
entre a primeira publicação da LCR revogada e a primeira execução em que o seu verificador passa a recusar.
`;

export const STARTER_EMITIR = `// Tarefas T1 e T2 (veja TASKS.md). Implemente emitirCredencial; não mude o nome nem a assinatura da função.

/**
 * Emite a credencial do agente, assinada com o e-CNPJ de teste da empresa (emissão pela própria empresa).
 *
 * @param {object} ctx
 * @param {Uint8Array} ctx.pfx            bytes do e-CNPJ A1 de teste (pki/empresa.pfx)
 * @param {string} ctx.senha              senha do .pfx
 * @param {string} ctx.cnpj               CNPJ da empresa
 * @param {{ kind: "evm", id: string }} ctx.agente  chave pública (endereço) do agente
 * @param {string[]} ctx.anchors          âncoras de confiança de teste (PEM)
 * @param {Date} ctx.agora                o momento da emissão
 * @returns {Promise<{ credential: object, proof: object }>}
 */
export async function emitirCredencial(ctx) {
  throw new Error("NAO_IMPLEMENTADO: emitirCredencial");
}
`;

export const STARTER_VERIFICAR = `// Tarefas T3 e T4 (veja TASKS.md). Implemente criarVerificador; não mude o nome nem a assinatura da função.

/**
 * Cria o verificador do marketplace (offline: sem emissor, sem rede).
 *
 * @param {object} ctx
 * @param {string[]} ctx.anchors                          âncoras de confiança de teste (PEM)
 * @param {() => Date} ctx.agora                          relógio do verificador (use este, não new Date())
 * @param {(url: string) => Promise<Uint8Array>} ctx.buscarCrl  bytes DER da LCR publicada nessa URL
 * @returns {Promise<(request: Request) => Promise<{ aceito: boolean, motivo?: string }>>}
 */
export async function criarVerificador(ctx) {
  return async (request) => {
    throw new Error("NAO_IMPLEMENTADO: criarVerificador");
  };
}
`;

export const QUESTIONS = [
  { id: "q1", text: "(1) Em qual tarefa você mais travou, e por quê?", optional: false },
  { id: "q2", text: "(2) O que no mandato (tetos, contrapartes, validade) foi confuso de expressar?", optional: false },
  { id: "q3", text: "(3) Que parte da documentação faltou ou atrapalhou?", optional: false },
  { id: "q4", text: "(4) Você usaria isto num sistema real? O que impediria?", optional: false },
  { id: "q5", text: "(5) Algo mais? (opcional, Enter para pular)", optional: true }
] as const;

export const LIBRARY_QUESTIONS = {
  changed: "Você alterou a biblioteca (arquivos em node_modules/@kya-brasil) ou teve de contorná-la para concluir? (s/n)",
  where: "Onde (pacote, arquivo ou função) e por quê?",
  request: "Que alteração você pediria na biblioteca? (opcional, Enter para pular)"
} as const;

export const CATEGORY_PT: Record<string, string> = {
  signature: "assinatura",
  icp_chain: "cadeia ICP / certificado",
  mandate: "mandato",
  revocation: "revogação",
  freshness: "validade / relógio",
  replay: "repetição (replay)",
  runtime: "erro de execução",
  other: "outro"
};

export const HINT_PT: Record<string, string> = {
  signature: "confira se a requisição/credencial foi assinada com a chave certa e se o corpo não mudou depois da assinatura.",
  icp_chain: "confira o .pfx, a senha e as âncoras (pki/anchors.pem): a cadeia precisa chegar até elas.",
  mandate: "releia o cenário e os campos do mandato (docs/choosing-parameters.md).",
  revocation: "o status do certificado vem da LCR: veja certificateStatus, verifyCrl e evidenceFromRevocation.",
  freshness: "confira datas e relógio: use ctx.agora/ctx.agora(), e respeite o nextUpdate da LCR.",
  replay: "o verificador precisa lembrar das requisições já aceitas (replayCache).",
  runtime: "a sua função lançou um erro; a mensagem está acima.",
  other: "confira o formato do retorno descrito no TASKS.md."
};
