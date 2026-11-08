# research/integration

Integration without participants, for Section 8.1 of the journal article (kya-paper, `revista/`). No people take
part. `measure.mjs` runs the study kit's four tasks (`packages/study-kit`: T1 issue, T2 policy, T3 offline verifier,
T4 revocation) on the reference solution in `packages/study-kit/test/fixtures/solution`, the same files the kit's
end-to-end test uses, `INTEGRATION_RUNS` times (default 20). Each run starts from a fresh workspace and a fresh
throwaway test PKI, with the network stubbed to fail.

```bash
pnpm --filter @kya-brasil/research-integration measure
```

`results.json` records the library versions, the machine, whether every task and sub-case passed in every run, the
accept latency the kit measures (ms, median and p95 over all valid purchases of T3 and T4), and what the solution
takes: lines that are not blank or comments, the library functions it imports, their call sites, and the packages.

The reference solution stays with the kit's tests and is not copied to `examples/`. The case study (H3), deferred
to a later study, asks participants to integrate from the documentation alone, and `examples/` is part of it.

Like the kit's own tests, the child process that runs the solution resolves `@kya-brasil/core` and
`@kya-brasil/agent-tools` to the workspace's TypeScript sources (tsx with `packages/study-kit/test/tsconfig.runner.json`);
a participant gets the published builds instead.
