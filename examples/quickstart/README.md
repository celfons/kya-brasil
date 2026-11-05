# Quickstart: self-issue a credential and verify an agent offline

Three scripts, run in order, that exercise the whole flow without the hosted service and without a real certificate.
CI runs them on every push (`.github/workflows/ci.yml`), so they track the current source.

> **TEST ONLY.** `make-test-pki.mjs` creates a throwaway, worthless "ICP-Brasil-like" PKI (root, intermediate AC,
> e-CNPJ and e-CPF A1 files, a CRL) with made-up CNPJ/CPF numbers and passwords in clear text. Never add
> `out/anchors.pem` to a real trust store. The real ICP-Brasil anchors are in [anchors/icp-brasil.pem](../../anchors/icp-brasil.pem).

```sh
pnpm install                                              # at the repository root
pnpm --filter @kya-brasil/examples-quickstart quickstart  # or, in this folder: pnpm quickstart
```

| Script | What it shows |
| --- | --- |
| [`make-test-pki.mjs`](make-test-pki.mjs) | Builds the test PKI with `@peculiar/x509` and WebCrypto (no `openssl`): root and intermediate AC, an e-CNPJ leaf with the otherName `2.16.76.1.3.3` (CNPJ), an e-CPF leaf with `2.16.76.1.3.1` (birth date + CPF), both as `.pfx`, the AC's CRL and an EVM agent key. Writes `out/` (or `$KYA_QUICKSTART_OUT`). |
| [`self-issue.mjs`](self-issue.mjs) | A company issues its own agent credential (D-37): `buildMandate` → `mandateSigningInput` → e-CNPJ signs → `assembleCredential` → `verifySelfIssuedCredential`, then a legal representative co-signs with an e-CPF (`addCosignature`) and `verifyCompanyWill` checks it against the verifier's list of representatives. Writes `out/credential.json`. |
| [`agent-and-verifier-offline.mjs`](agent-and-verifier-offline.mjs) | The agent signs a request with `signRequest({ …, present: { credential, proof } })`; the verifier uses `createKyaAuth({ offline, replayCache })` with a `certificateStatus` that verifies the AC's CRL (`verifyCrl`) and caches it until `nextUpdate`. R$ 100 is allowed, R$ 6.000 is refused (above `max_per_operation`), the same request replayed is refused (`KYA_REQUEST_REPLAYED`). |

Each script exits non-zero on any unexpected result.

## The same issuance from the terminal

[`mandate-input.json`](mandate-input.json) is the input `kya-sign --issue` reads: a `MandateInput` (`credential_id`,
`agent`, `principal`, `mandate` with every risk field stated, `ttl_seconds`; optional `now`, ISO date). Put your
agent's key in `agent` and your dates in `valid_from` / `valid_until`.

```sh
kya-sign --pfx empresa.pfx --issue mandate-input.json --anchors icp-brasil.pem --out credential.json
kya-sign --pfx representante.pfx --cosign credential.json --anchors icp-brasil.pem --out credential.cosigned.json
```

`--cosign` without `--out` **overwrites** the input file. `--pkcs11 <library>` (A3) or `--cloud <module>` instead of
`--pfx`. The password comes from `KYA_PFX_PASSWORD` (A1) or the PIN from `KYA_TOKEN_PIN` (A3), or is asked for.

## Imports

`package.json` depends on `@kya-brasil/core` and `@kya-brasil/agent-tools` as `workspace:*`, and `tsconfig.json`
maps both to their TypeScript source, which `tsx` runs directly. Outside this repository, install them from npm
and run the same files with plain `node`.
