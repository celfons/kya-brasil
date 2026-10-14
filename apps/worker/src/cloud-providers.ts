/**
 * Cloud e-CNPJ providers (PSCs) this deployment offers on /sign (D-28). Empty in this repository: each PSC has
 * its own contract, registration and API, so a self-hosted issuer adds its own implementations of
 * CloudSignatureProvider here (see examples/cloud-provider). Secrets (client id/secret) come from env.
 * With no provider, the cloud option is simply not shown.
 */
import type { CloudSignatureProvider } from "@kya-brasil/core";
import type { AppEnv } from "./env";

export function cloudProviders(_env: AppEnv): CloudSignatureProvider[] {
  return [];
}
