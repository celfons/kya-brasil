# research/bench: performance benchmarks (TEST ONLY PKI)

Reproducible latency and size measurements of `@kya-brasil/core` and `@kya-brasil/agent-tools`, run with `tsx`
against the workspace sources, on the throwaway ICP-Brasil-like PKI of
[`examples/quickstart/make-test-pki.mjs`](../../examples/quickstart/make-test-pki.mjs) (written to `./out`, worthless).

```sh
pnpm install
pnpm --filter @kya-brasil/research-bench bench          # full run, N=1000; rewrites results.json and RESULTS.md here
BENCH_N=200 pnpm --filter @kya-brasil/research-bench bench
pnpm --filter @kya-brasil/research-bench bench:smoke    # N=20, 1000-entry CRL, size-range assertions; writes to ./out only
```

Env: `BENCH_N` (iterations of fast operations, default 1000; slow ones use fewer and the table states N),
`BENCH_CRL_ENTRIES` (entries of the synthetic large CRL, default 77 000, the size class of the SERPRO RFB v5 CRL).

What is measured (each warmed up, then timed one call at a time; median, p95, ops/s = 1000 / median, one thread):

1. issuance: `buildMandate` + `mandateSigningInput` + e-CNPJ A1 signature (`openPfx`, detached CMS, RSA-2048) + `assembleCredential`; and the signature alone;
2. `verifySelfIssuedCredential` (principal's proof against the anchors);
3. `addCosignature` and `verifyCompanyWill` (one e-CPF co-signer);
4. agent `signRequest`, and full offline `createKyaAuth({ offline, replayCache }).authenticate` + `check()` of an action (CRL verified once and cached, as a verifier would);
5. `verifyDelegationChain` at depth 1, 2, 3;
6. `checkRevocation` / `verifyCrl` + `lookup` on the small test CRL and on a synthetic large CRL (own throwaway AC, random serials): parse+verify and lookup timed separately;
7. sizes in bytes: credential JSON, `KYA-Principal-Proof` (with and without one co-signature), all request headers, `KYA-Delegation` per depth, CRLs.

Output: [`results.json`](results.json) (environment: date, Node/V8/OpenSSL, OS, CPU model from `os.cpus()`, package
versions, `GITHUB_RUN_ID` when in CI; every result with min/mean/max too) and [`RESULTS.md`](RESULTS.md).

**Absolute times vary between machines** (CPU, turbo, noisy neighbours on shared runners). Compare medians measured
on the same machine, not across machines. CI only runs the smoke step (no timing thresholds); the full run is the
manual `Benchmark` workflow (`.github/workflows/bench.yml`, input `n`), which prints RESULTS.md to the job summary.

**Finding (CRL size), fixed in core 0.19.1.** Up to core 0.19.0, `verifyCrl` (through `@peculiar/x509`'s `X509Crl`
and asn1js's default `maxNodes` = 10 000) refused CRLs above about 1 240 entries, so the AC SERPRO RFB v5 CRL
(~77 000 entries) could not be verified. Core 0.19.1 reads CRLs with a bounded DER reader of its own. Section 6b
measures the library on a synthetic CRL generated with the `openssl` CLI (`BENCH_CRL_ENTRIES`); 6c on the latest real
SERPRO RFB v5 CRL from the public kya-icp collector, verified against `anchors/icp-brasil.pem` (full runs only, needs
network; `BENCH_SERPRO=0` skips it). The "before" numbers are kept in `findings` of results.json.
