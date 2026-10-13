# Contributing

Issues and pull requests are welcome, in Portuguese or English.

- `pnpm install`, `pnpm typecheck`, `pnpm test` must pass. CI runs the same.
- Changes to the credential format, the challenge text, the mandate schema or the verification
  procedure are changes to `docs/SPEC.md` first; keep the test vectors in sync (`GEN_VECTORS=1` on
  `packages/core/src/vectors.test.ts` regenerates them, with a new throwaway key).
- Fields under `/v1` are only added, never renamed or removed.
- Never add personal data of natural persons to anything stored or returned.
- Secrets never go in the repository: `.dev.vars` locally, GitHub environments for the cloud.

Nothing closed is needed to run or test the issuer. KYB Brasil, a separate closed product, is an optional
source: when it is configured the issuer reads the registration status (and the informative risk snapshot)
from it, otherwise from the Receita's open data through BrasilAPI / CNPJ.ws (`apps/worker/src/registration.ts`,
D-17). Running your own issuer: `docs/SELF-HOSTING.md`. Code of conduct: `CODE_OF_CONDUCT.md`.
