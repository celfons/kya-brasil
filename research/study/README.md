# Case study (H3): independent integration from the docs alone

Hypothesis H3 of the pre-registration (osf.io/t59kv, `docs/research/pedido-iti-osf-zenodo.md`): *an independent
developer integrates KYA using only the documentation, without changing the library.* Pre-registered measures:
time to the first correct verification, changes requested to the library ("alterações pedidas na biblioteca"),
and time until a revocation takes effect ("tempo até a revogação valer").

The instrument is [`@kya-brasil/study-kit`](../../packages/study-kit) (`kya-study`), which runs on the
participant's computer. This folder holds the protocol and `analyze.py`, which aggregates the reports.

## Protocol

0. **Before inviting anyone.** Publish `@kya-brasil/study-kit` to npm (the *Publish npm package* workflow) at
   the same time as, or after, the `@kya-brasil/core` and `@kya-brasil/agent-tools` versions it depends on, then
   run step 2 yourself in an empty folder outside the repository: `npx` must find the kit and `npm install` in
   the new workspace must finish without a 404. The workspace's `package.json` references the kit as it was
   installed (the npm version, or the `file:` path of a local `.tgz` for a dry run, which must then stay where it
   is). For a dry run from a tarball use `npx --package ./kya-brasil-study-kit-<v>.tgz kya-study init` (npm takes a
   bare absolute path for a command, not a package). The test PKI is valid from one day before `init` to one year
   after it.
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
   usually fits in two hours. The library READMEs include snippets close to the tasks on purpose: H3 is about
   integrating from the docs, and the time and errors on the way are the measure. **Web search and AI assistants (ChatGPT, Copilot, Claude etc.) are allowed and
   recorded**: `TASKS.md` says so, `finish` asks whether the participant used an AI assistant and in which tasks,
   and `analyze.py` splits the results by AI used / not used / no answer. The pre-registered hypothesis is about
   the documentation; results with AI are reported separately and labelled exploratory.
3. **End.** `npx kya-study finish` (five open questions, the AI-assistant question and the library-change
   question; at the end of input, e.g. `< /dev/null`, it stops and records the rest as unanswered; Ctrl-C saves
nothing; running it again asks before replacing the earlier answers, and keeps them unless the new round is
confirmed and completed) and
   `npx kya-study send`, which writes `kya-study-report-<id>.json`, shows what goes where, asks, and posts it to the
   study inbox (kya-icp, `POST /study/reports`; kept in R2 under `study/reports/`, no IP address, nothing served
   back). The sender is not known to the researcher. `report` plus a manual channel remains possible.
4. **Analysis.** Put the reports in one folder and run `python3 -I analyze.py <folder>` (standard library only).
   It writes `summary.md`, `participants.csv`, `tasks.csv` and `answers.md` (open answers grouped by question,
   for qualitative coding) to `<folder>/analysis`. A file that is not valid JSON or does not have the report's
   structure is skipped and listed in `summary.md` with the reason; it never stops the analysis.

### Rigor: what makes the case study checkable

- **Documentation freeze.** `TASKS.md` links to the documentation at the git tag `study-h3-docs-1`, not to `main`.
  Every participant reads the same text. Corrections found during the collection are made on `main` and reported
  as a result; the tag does not move. The report also records the library and kit versions.
- **Sample rule.** The first 3 complete reports (`finish` done), by date received, are the confirmatory sample;
  later ones are exploratory. Declared in the OSF transparent-changes document before the first report.
- **Post-session interview (optional, 15–20 min).** A short guided conversation after `report`, taken as written
  notes, not recorded. It deepens the integration diary and is coded with the same codebook.
- **Codebook.** [codebook.md](codebook.md), written before any report was read: two coders, agreement reported,
  every claim backed by a coded passage and a measured datum, member checking with each participant.
- **Raw data.** With the participants' consent (stated in the consent text), the anonymous reports and the output
  of `analyze.py` are archived with a DOI, so anyone can rebuild the tables.
- **Author's pilot.** Excluded from every analysis: the author is not independent and used the reference solution.

### Scenario and tasks

"A company lets an AI agent buy office supplies from supplier X, up to R$ 500 per purchase and R$ 1,500 per day,
for 30 days, without delegating." Everything runs against a throwaway test PKI (fake e-CNPJ, e-CPF, AC, CRL),
created by `init` and marked TEST ONLY.

| Task | What the participant does | How it is graded |
| --- | --- | --- |
| T1 issue | builds and signs the mandate and credential with the test e-CNPJ (self-issued) | `verifySelfIssuedCredential` against the test anchors, and the agent must be the given key |
| T2 policy | nothing new: the mandate T1 produced | compared with the answer key: correct, too permissive (higher ceilings, any counterparty, extra actions or currencies, delegation, longer validity), too restrictive, or invalid; every deviating field recorded |
| T3 verify | an offline verifier (`createKyaAuth` offline + `check()`) | requests signed with the kit's own reference credential, in a random order: three in-mandate purchases with random amounts (accept); above the ceiling, another supplier, tampered request signature, body changed after signing, credential from an AC outside the anchors, request signed by another key, tampered mandate, a replay of one of the valid purchases, always after it (refuse). A refusal counts only when every valid purchase was accepted, so neither a verifier that only reads the JSON body nor one that counts requests passes |
| T4 revocation | the same verifier | a sequence of CRLs, each at a random clock step past the previous one's `nextUpdate`, with one or two purchases each: the current CRL (accept); two to four re-issued CRLs, at least one plain and at least one revoking two to four other certificates (accept, so "the bytes changed", "the list grew", "the Nth fetch" or "after some minutes" are not taken for a revocation); once, no new CRL in time, so `buscarCrl` keeps serving the expired one (refuse with the library's stale/unavailable status code: fail closed); the CRL that revokes the company certificate, which also drops old entries so it is never longer than the CRLs before it, and one more re-issue of it (refuse, with `KYA_CERTIFICATE_REVOKED` in `motivo`) |

Every CRL is issued fresh at each `check`, so the tasks do not expire with the `pki/ac.crl` written at `init`.
Each call into the participant's code runs in a child process with a timeout (10 s per verification call by default,
three times that for loading the modules and for T1's issuance; `KYA_STUDY_TIMEOUT_MS` changes the base); a
verifier that never answers or an issuer stuck in a loop is recorded as `timeout`, not as a hang.

The T4 timer starts the first time the kit publishes the revoked CRL, which happens in the first T4 run whose
pre-revocation purchase is accepted; it stops at the first passing T4 run. T2's first grade (the first
verifiable mandate) is the policy-quality measure; later grades may reflect the kit's own feedback.

### What is recorded

Per `check` attempt (`.kya-study/log.jsonl`, local): time, task, pass/fail, error category (`signature`,
`icp_chain`, `mandate`, `revocation`, `freshness`, `replay`, `runtime`, `timeout`, `contract` (the function
returned the wrong shape), `other`, mapped from the library's error codes and check rules; a wrong `.pfx`
password is `icp_chain`), per-sub-case results, policy grade and deviating fields (field names and counts only,
never the values the participant wrote), duration of each verification call (the latency metric uses only the
calls where the valid purchase was accepted). At `report`: the counts of files and lines changed against the starter project (git `--numstat` against a
baseline commit made at `init`, or a snapshot of line hashes when git is missing; `node_modules`, the test PKI,
the kit's state and lock files excluded), whether the installed library files
(`node_modules/@kya-brasil/{core,agent-tools}`) changed after the participant's first `check`
(`library_integrity`, measured with a digest; only yes/no reaches the report; a change made before the first
`check` is not seen, and editing the library could also affect the grading, which uses the same copy), the open
answers, the AI-assistant answer
(`ai_assistant: { used, tasks }`) and the library-change answer.

**Not recorded, and not in the report:** code, file names or paths, names, e-mail, user name, host name or any
machine identifier, network data. The OS is reported as a family (`linux`, `macos`, `windows`), the date as year
and month. Free-text answers are scrubbed of every absolute path (`/a/b`, `C:\a`, `\\server\share`, `~/a`;
the user name goes with them), the host name and e-mail addresses; ordinary words are kept. The
kit's only network call is `send`, run and confirmed by the participant; nothing leaves the computer before.

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
