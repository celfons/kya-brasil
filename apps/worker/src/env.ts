/**
 * `wrangler types` generates `Env` from wrangler.jsonc; cloud-only bindings and secrets are added here.
 */
export type AppEnv = Env & {
  /** Service Binding to the KYB Brasil Worker (cloud). Absent locally: KYB_URL + fetch instead. */
  KYB?: Fetcher;
  /** Local dev only: public URL of a KYB worker (wrangler dev on another port). */
  KYB_URL?: string;
  /** Shared key for KYB's /internal/v1/* routes (never billed through x402). */
  KYB_INTERNAL_KEY?: string;
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
  CDP_API_KEY_ID?: string;
  CDP_API_KEY_SECRET?: string;
};
