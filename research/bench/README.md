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

**Finding (CRL size).** `verifyCrl` (through `@peculiar/x509`'s `X509Crl` and asn1js's default `maxNodes` = 10 000)
refuses CRLs above about 1 240 entries with "Maximum ASN.1 node count exceeded", so a CRL the size of the SERPRO RFB v5
one (~77 000 entries, ~3.7 MB) cannot be verified today. The benchmark records this under `findings`, measures the
largest CRL accepted, and, as a reference, what parse+verify+index of the full CRL costs with the limit raised
(asn1js + `node:crypto`, outside the library's code path). The large CRL is generated with the `openssl` CLI.
