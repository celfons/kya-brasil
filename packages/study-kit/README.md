# @kya-brasil/study-kit

The experiment kit for the KYA Brasil case study (hypothesis H3: *an independent developer integrates KYA using
only the documentation, without changing the library*). It measures use and implementation objectively, ends with
a short open questionnaire, and writes **one anonymous report file** that the participant sends to the researcher.

- **Local only.** No telemetry in the libraries, no network calls by the kit. State lives in the workspace's
  `.kya-study/` folder until the participant sends the report.
- **Throwaway test PKI.** `init` creates a fake e-CNPJ, e-CPF, AC and CRL, marked TEST ONLY. Never trust them.
- **Graded with the library itself.** Every task is checked with `@kya-brasil/core` and
  `@kya-brasil/agent-tools`, not by reimplementing their rules.

Protocol, ethics and the analysis script: [research/study](../../research/study).

## Commands

```sh
npx @kya-brasil/study-kit init [dir]   # consent (type "aceito"), then the workspace (default: ./estudo-kya)
cd estudo-kya && npm install
npx kya-study check [t1|t2|t3|t4]       # grade one task or all; run as often as needed
npx kya-study finish                    # five open questions, "did you use an AI assistant?", "did you change the library?"
npx kya-study report                    # writes kya-study-report-<id>.json
```

`--dir <folder>` points `check`, `finish` and `report` at a workspace; otherwise the current folder or a parent
of it is used.

### `init`

Shows the consent text (Portuguese): what is collected (timestamps, task results, error categories, policy
grading, line/file counts, latency, open answers, whether an AI assistant was used) and what is not (code, name, e-mail, machine identifiers,
network data). Only `aceito` continues. Then it creates:

| Path | What |
| --- | --- |
| `TASKS.md` | scenario and the four tasks (Portuguese) |
| `package.json` | depends on the published `@kya-brasil/core` and `@kya-brasil/agent-tools`, and on this kit as it was installed (npm version, or the `file:` path of a local `.tgz`) |
| `src/emitir.mjs`, `src/verificar.mjs` | the functions to implement, with their signatures |
| `pki/` | `anchors.pem`, `ac.crl`, `empresa.pfx` (e-CNPJ), `representante.pfx` (e-CPF), `agente.json`, `pki.json`: TEST ONLY |
| `.kya-study/` | `config.json` (random participant id, start time, kit version, baseline), the AC key for new CRLs, `log.jsonl`, `answers.json` |

With git available it runs `git init` and commits the starter project (neutral author, no signing) as the
baseline for change counts; without git it keeps a snapshot of line hashes instead.

### `check`

Runs the participant's modules in a child process, with a timeout per call (10 s by default, 30 s for
loading the modules and for T1; `KYA_STUDY_TIMEOUT_MS` sets the base), and grades each task, appending one JSON line per attempt to
`.kya-study/log.jsonl` (time, task, pass, error category, sub-cases, verification durations in ms) and printing
feedback in Portuguese.

| Task | Participant implements | Graded by |
| --- | --- | --- |
| T1 issue | `emitirCredencial(ctx)` → `{ credential, proof }`, self-issued with the test e-CNPJ | `verifySelfIssuedCredential` with the test anchors; the agent must be `pki/agente.json` |
| T2 policy | (the T1 mandate) | the answer key in `src/policy.ts`: `correct`, `permissive`, `restrictive` or `invalid`, with the deviating fields |
| T3 verify | `criarVerificador(ctx)` → `async (request) => ({ aceito, motivo })`, offline | requests signed with the kit's own reference credential, in a random order: three in-mandate purchases (accept); above the ceiling, another supplier, tampered signature, body changed after signing, AC outside the anchors, another signing key, tampered mandate, replay (refuse). Refusals count only when every valid purchase was accepted |
| T4 revocation | the same verifier | CRLs at random clock steps (`ctx.agora()` past the previous `nextUpdate`), one or two purchases each: current CRL and two to four re-issues, one revoking another certificate (accept); the CRL revoking the company certificate and a re-issue of it (refuse with `KYA_CERTIFICATE_REVOKED` in `motivo`) |

The CRLs are issued fresh at every `check` (the `pki/ac.crl` written at `init` is only an example to read).

Error categories: `signature`, `icp_chain`, `mandate`, `revocation`, `freshness`, `replay`, `runtime`,
`timeout`, `contract` (wrong return shape), `other`, mapped from the library's error codes (`KYA_*`, `KyaError`
codes) and check rules (`src/errors.ts`). A wrong `.pfx` password is `icp_chain`. Syntax and import errors are
shown with the file and line.

`ctx` for T1: `pfx`, `senha`, `cnpj`, `agente`, `anchors`, `agora` (a `Date`). For T3/T4: `anchors`, `agora()`
(the verifier's clock, controlled by the kit in T4) and `buscarCrl(url)` (stands in for fetching the CRL).

### `finish` and `report`

`finish` asks the five open questions, whether the participant used an AI assistant (allowed) and in which
tasks, and whether they changed (or worked around) the library, and where; at the end of input it stops asking
and records the rest as unanswered; Ctrl-C saves nothing; a second `finish` asks before replacing the answers.
`report` writes `kya-study-report-<id>.json` in the workspace:

- kit and library versions, Node.js version, OS family, year-month of the session;
- per task: attempts, passes, pass rate, seconds from start to the first success, attempts until it, error counts
  by category, sub-case pass rates (T3, T4);
- policy grade and deviating fields, as field names and counts only (first verifiable mandate and last one);
- T4: when the revoked CRL was published and the seconds until the first passing run;
- verification latency (median, p25, p75) of the calls where the valid purchase was accepted;
- files and lines changed against the baseline (excluding `node_modules`, `out`, `dist`, `pki`, `.kya-study`,
  lock files);
- `ai_assistant: { used, tasks }`;
- `library_integrity: { checked, modified, versions_changed }`: whether `node_modules/@kya-brasil/{core,agent-tools}`
  changed after the first `check` (a digest kept in `.kya-study/config.json`; no file names in the report);
- the open answers and the library-change answer, scrubbed of every absolute path (the user name goes with
  it), the host name and e-mail addresses.

No code, no paths, no host name, no user name.

## Development

```sh
pnpm --filter @kya-brasil/study-kit typecheck
pnpm --filter @kya-brasil/study-kit test     # e2e: a simulated participant in a temporary folder
pnpm --filter @kya-brasil/study-kit build    # dist/ (needs @kya-brasil/agent-tools built first)
```

The tests' reference solution lives in `test/fixtures/` and is **not** published (`files` is `dist` and this
README): participants never see an answer. In the monorepo the starter project's library versions come from the
workspace packages; the publish workflow replaces `workspace:*` with the versions published just before.

## Para participantes

Obrigado por participar! Você vai integrar a biblioteca KYA Brasil a partir da documentação, em quatro tarefas
curtas (emitir um mandato, conferir a política, verificar pedidos offline e lidar com uma revogação), e responder
cinco perguntas no fim. Busca na web e assistentes de IA são permitidos; no fim o kit pergunta se você usou.

1. Numa pasta vazia: `npx @kya-brasil/study-kit init estudo-kya`. Leia o termo e digite `aceito`.
2. `cd estudo-kya && npm install`, e leia o `TASKS.md`.
3. Implemente `src/emitir.mjs` e `src/verificar.mjs` e rode `npx kya-study check` quantas vezes quiser.
4. No fim: `npx kya-study finish` e `npx kya-study report`. Envie ao pesquisador **só** o arquivo
   `kya-study-report-<id>.json` (você pode abri-lo antes).

O kit não faz nenhuma conexão de rede e não guarda seu código, nome, e-mail nem dados da máquina. Os certificados
da pasta `pki/` são de teste, sem valor. Você pode parar a qualquer momento: é só não enviar o relatório e apagar
a pasta.
