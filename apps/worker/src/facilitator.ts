import { createFacilitatorConfig } from "@coinbase/x402";
import type { FacilitatorConfig } from "@x402/core/server";
import type { AppEnv } from "./env";

/**
 * Facilitator selection (SPEC §6.1):
 * - testnet: public https://x402.org/facilitator, no auth.
 * - mainnet: Coinbase CDP facilitator, authenticated with CDP_API_KEY_ID / CDP_API_KEY_SECRET.
 * The URL comes from X402_FACILITATOR_URL either way; auth headers are added only when
 * both CDP secrets exist, so a dev stack never needs them.
 */
export function facilitatorConfig(env: AppEnv): FacilitatorConfig {
  if (env.CDP_API_KEY_ID && env.CDP_API_KEY_SECRET) {
    const cdp = createFacilitatorConfig(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET);
    return { ...cdp, url: env.X402_FACILITATOR_URL || cdp.url };
  }
  return { url: env.X402_FACILITATOR_URL };
}
