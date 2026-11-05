# Handoff: study-kit (H3 case-study kit) — work in progress

Branch: `claude/intelligent-hamilton-rvhyrj` (kya-brasil). Not merged; no PR open. Nothing published to npm.

## Done (commit a6716dc)
`packages/study-kit` (`@kya-brasil/study-kit`, bin `kya-study`: init / check / finish / report) and
`research/study/` (protocol README + `analyze.py`). 13 tests passed at that commit.

## In progress (WIP commit on top; tests NOT re-run, may fail)
An independent QA found the bugs below; fixes were being applied when the session stopped. Check each, finish,
add regression tests (`src/regressions.test.ts` was started), run `pnpm -r typecheck && pnpm -r test`.

1. HIGH: interactive `init`/`finish` never exit in a real TTY (readline in `defaultIo()` not closed). Test: `test/pty-run.py`.
2. T3 fails after 7 days: T3 serves `pki/ac.crl` from init (nextUpdate = init + 7 d). Issue a fresh CRL per check.
3. `check` has no timeout (hang / never-resolving promise). Run participant code in a child process with a per-call timeout (`src/runner.ts`, `src/sandbox.ts` started); category `timeout`.
4. HIGH (research validity): T3/T4 pass a verifier that checks no cryptography. Add negative cases: tampered request signature, body changed after signing, untrusted CA, wrong agent key, tampered mandate; in T4 re-issue an identical CRL so "bytes changed => revoked" fails. Fixture `test/fixtures/blind/` should FAIL.
5. Wrong .pfx password mapped to `mandate`; map to `icp_chain` (fixture `badpass/`).
6. `finish < /dev/null` loops forever after EOF.
7. `scrub()` replaces the username as a word in free text; must only strip it in paths, and redact any absolute path.
8. Report leaks participant identifiers in policy deviation details; report field names/counts only.
9. Malformed verifier return (`{ok:true}`) should be category `contract` (fixture `contract/`).
10. Latency median only from calls where the valid purchase was accepted.
11. Syntax/import errors: show file and line (fixture `syntax/`).
12. `analyze.py`: skip structurally wrong JSON with a reason instead of crashing.
13. User decision: web search and AI assistants ALLOWED and RECORDED. TASKS.md says so; `finish` asks
    "Usou assistente de IA (ChatGPT, Copilot, Claude etc.)? (sim/não)" + "Em quais tarefas?"; report field
    `ai_assistant: { used, tasks }`; `analyze.py` breaks results down by AI used vs not.
14. `packages/agent-tools/README.md` offline example must use the verifier's injected clock (not Date.now()) for the CRL cache and verifyCrl.
15. `research/study/README.md`: study-kit must be published to npm before inviting participants; participant package.json must install without 404.

QA repro material (in the previous session's scratchpad, may be gone): tools/tty.py, tools/shift.mjs.

## After fixes
1. Re-run an independent QA as a participant: `pnpm pack` core, agent-tools, study-kit; install in an empty dir
   outside the repo; do the 4 tasks from TASKS.md + public docs only; error paths; report privacy; analyze.py.
2. Open PR to main, wait for CI (SonarCloud too), merge.
3. Ask the user before publishing `@kya-brasil/study-kit` to npm (Publish npm package workflow).
4. Then: a one-line mention in the paper (kya-paper, Discussion / future work: the kit as the instrument for H3) and
   optionally in the pre-project, keeping 16 pages (paper: body ends p.14) and 9 pages (pre-project).

## Other open items (context)
- Paper (private repo celfons/kya-paper): 16 pages = limit (14 body + 2 refs); zero slack.
- Pre-registration OSF: osf.io/t59kv (embargo until 2027-11-07). The kit's open questionnaire covers the
  pre-registered "integration diary"; extra instrumented metrics are exploratory and must be labelled so.
- Data DOI v2: 10.5281/zenodo.23985090. Core code DOI 10.5281/zenodo.23973230. Collector code 10.5281/zenodo.23973109.
- ITI LAI request NUP 00137.011046/2026-56 (answer due ~2026-11-25).
- Root-chain CRLs (AC Raiz v6/INMETRO Ed448; AC Raiz v7 OID 1.3.6.1.4.1.44588.2.1) are refused by core's CRL reader
  (fail closed). End-user CRLs (RSA) all work. User said they would handle the core PR elsewhere.
