# Contributing

Issues and pull requests are welcome, in Portuguese or English.

- `pnpm install`, `pnpm typecheck`, `pnpm test` must pass. CI runs the same.
- Changes to the credential format, the challenge text, the mandate schema or the verification
  procedure are changes to `docs/SPEC.md` first; keep the test vectors in sync (`GEN_VECTORS=1` on
  `packages/core/src/vectors.test.ts` regenerates them, with a new throwaway key).
- Fields under `/v1` are only added, never renamed or removed.
- Never add personal data of natural persons to anything stored or returned.
- Secrets never go in the repository: `.dev.vars` locally, GitHub environments for the cloud.

KYB Brasil, the company-check service this issuer depends on, is a separate closed product. Its client
here is `apps/worker/src/kyb.ts`; a different KYB provider is a different implementation of that file.
