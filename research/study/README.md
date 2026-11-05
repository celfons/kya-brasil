# Case study (H3): independent integration from the docs alone

Hypothesis H3 of the pre-registration (osf.io/t59kv, `docs/research/pedido-iti-osf-zenodo.md`): *an independent
developer integrates KYA using only the documentation, without changing the library.* Pre-registered measures:
time to the first correct verification, changes requested to the library ("alterações pedidas na biblioteca"),
and time until a revocation takes effect ("tempo até a revogação valer").

The instrument is [`@kya-brasil/study-kit`](../../packages/study-kit) (`kya-study`), which runs on the
participant's computer. This folder holds the protocol and `analyze.py`, which aggregates the reports.

## Protocol

1. **Recruitment.** Developers who have not worked on KYA Brasil. Nothing about them is recorded by the kit; if
   the study needs a profile (years of experience, Node.js familiarity), collect it separately, anonymously, and
   link it only through the participant's random id, which they can copy from the report.
2. **Session.** The participant runs, in an empty folder of their choice:

   ```sh
   npx @kya-brasil/study-kit init estudo-kya
   cd estudo-kya && npm install
   ```

   `init` shows the consent text (Portuguese) and continues only when they type `aceito`. The study clock starts
   at that moment. They read `TASKS.md` (scenario and four tasks), implement `src/emitir.mjs` and
   `src/verificar.mjs`, and run `npx kya-study check` as often as they like. There is no time limit; a session
   usually fits in two hours. Whether other sources (web search, AI assistants) are allowed is a protocol
   decision; the default `TASKS.md` asks participants to say in the last question which ones they used.
3. **End.** `npx kya-study finish` (five open questions and the library-change question) and
   `npx kya-study report`, which writes `kya-study-report-<id>.json`. The participant reads it if they want and
   sends that one file to the researcher by the agreed channel.
4. **Analysis.** Put the reports in one folder and run `python3 -I analyze.py <folder>` (standard library only).
   It writes `summary.md`, `participants.csv`, `tasks.csv` and `answers.md` (open answers grouped by question,
   for qualitative coding) to `<folder>/analysis`.

### Scenario and tasks

"A company lets an AI agent buy office supplies from supplier X, up to R$ 500 per purchase and R$ 1,500 per day,
for 30 days, without delegating." Everything runs against a throwaway test PKI (fake e-CNPJ, e-CPF, AC, CRL),
created by `init` and marked TEST ONLY.

| Task | What the participant does | How it is graded |
| --- | --- | --- |
| T1 issue | builds and signs the mandate and credential with the test e-CNPJ (self-issued) | `verifySelfIssuedCredential` against the test anchors, and the agent must be the given key |
| T2 policy | nothing new: the mandate T1 produced | compared with the answer key: correct, too permissive (higher ceilings, any counterparty, extra actions or currencies, delegation, longer validity), too restrictive, or invalid; every deviating field recorded |
| T3 verify | an offline verifier (`createKyaAuth` offline + `check()`) | the kit sends requests signed with its own reference credential: an in-mandate purchase (accept), above the ceiling, another supplier, a replay (refuse); a refusal counts only when the valid purchase was accepted |
| T4 revocation | the same verifier | purchase accepted; the kit publishes a CRL that revokes the company certificate and moves the verifier's clock past the old CRL's `nextUpdate`; the next purchase must be refused for revocation |

The T4 timer starts the first time the kit publishes the revoked CRL, which happens in the first T4 run whose
pre-revocation purchase is accepted; it stops at the first passing T4 run. T2's first grade (the first
verifiable mandate) is the policy-quality measure; later grades may reflect the kit's own feedback.

### What is recorded

Per `check` attempt (`.kya-study/log.jsonl`, local): time, task, pass/fail, error category (`signature`,
`icp_chain`, `mandate`, `revocation`, `freshness`, `replay`, `runtime`, `other`, mapped from the library's error
codes and check rules), per-sub-case results, policy grade and deviating fields, duration of each verification
call. At `report`: the counts of files and lines changed against the starter project (git `--numstat` against a
baseline commit made at `init`, or a snapshot of line hashes when git is missing; `node_modules`, the test PKI,
the kit's state and lock files excluded), the open answers and the library-change answer.

**Not recorded, and not in the report:** code, file names or paths, names, e-mail, user name, host name or any
machine identifier, network data. The OS is reported as a family (`linux`, `macos`, `windows`), the date as year
and month. Free-text answers are scrubbed of the home directory, user name, host name and e-mail addresses. The
kit makes no network connection; nothing leaves the computer until the participant sends the report.

## Ethics

The participant's consent is recorded locally (the time they typed `aceito`); they can stop at any time by not
sending the report and deleting the folder. No identifying data is collected, so a report cannot be traced back
to a person unless they choose to say which id is theirs.

**When the study is run within a graduate program, submit it to a research ethics committee (CEP, through
Plataforma Brasil) before recruiting**, under Resolução CNS 510/2016 (human and social sciences). That
resolution exempts some studies with unidentified participants (art. 1, sole paragraph), but whether this one
qualifies is for the committee or the program to say, not the researcher. Attach the
consent text (shown by `kya-study init`; source in `packages/study-kit/src/texts.ts`), the task statements
(`TASKS.md`), the questionnaire, and this description of what is recorded. Any change to those texts after
approval must go back to the committee.
