// Mutation testing of the rules of @kya-brasil/core. Run from packages/core (see package.json, script "run").
// The files are the ones the article's claims rest on: the mandate and its containment, delegation, issuance,
// the principal's proof, the ICP-Brasil signature, the CRL reader and its verification, freshness, the co-signature
// and the time-stamp. Tests and test data are not mutated.
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Five batches, so that each run stays well under two hours on four cores. KYA_MUTATION_BATCH picks one.
const BATCHES = {
  mandate: ["src/mandate.ts", "src/delegation.ts"],
  issuance: ["src/issuance.ts", "src/principal-proof.ts"],
  policy: ["src/freshness.ts", "src/cosign.ts"],
  pki: ["src/crl-der.ts", "src/revocation.ts", "src/icp-brasil.ts", "src/timestamp.ts"],
  credential: ["src/attestation.ts", "src/credential.ts", "src/challenge.ts", "src/person.ts", "src/cnpj.ts"]
};
const batch = process.env.KYA_MUTATION_BATCH;
if (!BATCHES[batch]) throw new Error(`KYA_MUTATION_BATCH must be one of ${Object.keys(BATCHES).join(", ")}`);

export default {
  plugins: [require.resolve("@stryker-mutator/vitest-runner")],
  testRunner: "vitest",
  mutate: BATCHES[batch],
  coverageAnalysis: "perTest",
  concurrency: 4,
  timeoutMS: 60000,
  reporters: ["json", "clear-text", "progress"],
  jsonReporter: { fileName: join(here, "data", `mutation-${batch}.json`) },
  clearTextReporter: { logTests: false, reportTests: false, reportMutants: false, allowColor: false },
  // In place: the tests read docs/vectors by relative path, which a copy of the package elsewhere would break.
  // Stryker restores the files when it ends; after an interrupted run, `git checkout packages/core/src` does.
  inPlace: true,
  incremental: false
};
