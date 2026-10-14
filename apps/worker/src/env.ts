/**
 * `wrangler types` generates `Env` from wrangler.jsonc; cloud-only bindings and secrets are added here.
 */
export type AppEnv = Env & {
  /** Optional (D-23): BrasilAPI-format endpoint for the registration status, tried before the public mirrors; "{cnpj}" is replaced. */
  CNPJ_API_URL?: string;
  /** D-24: "off" skips the registration status check; default on. Failures never block issuance, they become warnings. */
  REGISTRATION_CHECK?: string;
  /** Secret. Receiving wallet address. */
  PAY_TO: `0x${string}`;
  /** Public base URL of this deployment, used inside credentials (issuer, verify_url). */
  ISSUER_URL?: string;
  /** Secret: Ed25519 private key (PKCS#8 base64) that signs credentials. Generated once by the CD. */
  ATTEST_PRIVATE_KEY?: string;
  ATTEST_PREVIOUS_KEYS?: string;
  /** Optional: shared key for the fiat channel (/internal/v1/*), billed by invoice. */
  INTERNAL_API_KEY?: string;
  /** Dev only: PEM bundle of ICP-Brasil roots; in the cloud the bundle lives in KV under icp:anchors. */
  ICP_ANCHORS_PEM?: string;
  /** Optional: JSON object chainId → RPC URL for ERC-8004 lookups (defaults: public Base and Ethereum endpoints). */
  EVM_RPC_URLS?: string;
  /** Optional: Glama connector claim token, served at /.well-known/glama.json. */
  GLAMA_CLAIM?: string;
  /** D-29 secret: JSON {"1": "<base64, 32+ bytes>"} of HMAC keys for CPFs; highest version is current. Absent = no person credentials. */
  PERSON_HMAC_KEYS?: string;
  CDP_API_KEY_ID?: string;
  CDP_API_KEY_SECRET?: string;
};
