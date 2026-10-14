/// <reference types="node" /> // test-only: Buffer, node:fs, process
/**
 * Test vectors for "KYA Credential v1" (docs/SPEC.md), kept in docs/vectors/credential-v1.json so other
 * implementations can check their verifier against ours. Regenerate with GEN_VECTORS=1 (new throwaway key).
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { generateAttestationKey, importPrivateKey, signAttestation, verifyAttestation } from "./attestation.js";
import { challengeText } from "./challenge.js";
import { buildCredential, signCredential, verifyCredentialSignature } from "./credential.js";
import { checkAction } from "./mandate.js";
import type { AgentKey, Credential, KybSnapshot, Mandate } from "./types.js";

const FILE = new URL("../../../docs/vectors/credential-v1.json", import.meta.url);

async function generate() {
  const key = await generateAttestationKey();
  const priv = await importPrivateKey(key.privateKeyPkcs8);
  const now = new Date("2026-10-13T00:00:00.000Z");
  const issuer = "https://kya.example";
  const agent: AgentKey = { kind: "evm", id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" };
  const cnpj = "11222333000181";
  const mandate: Mandate = { actions: ["quote", "order", "pay"], max_per_operation: { amount: 5000, currency: "USDC" }, max_per_day: { amount: 20000, currency: "USDC" }, currencies: ["USDC"], counterparties: ["33000167000101", "*.beta.com.br"], valid_until: "2027-01-01T00:00:00Z", notes: "free-form fields are kept but not evaluated" };
  const kyb: KybSnapshot = { risk_level: "low", risk_score: 5, registration_status: "ATIVA", active_sanctions: 0, forced_labor: false, federal_debt_brl: null, active_embargoes: 0, red_flags: [], checked_at: now.toISOString() };
  const challenge = { issuer, challenge_id: "0f6e1c2a-6b1d-4c0e-9f9a-2b0b3c4d5e6f", agent, cnpj, expires_at: "2026-10-13T00:15:00.000Z" };
  const unsigned = buildCredential({ credential_id: "6d0b1c2e-1111-4222-8333-444455556666", agent, cnpj, legal_name: "ACME LTDA", registration_status: "ATIVA", certificate: { sha256: "3b7a0e5a1d9c8f2b6e4d1a0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a", subject: "CN=ACME LTDA:11222333000181, OU=AC Exemplo RFB, O=ICP-Brasil, C=BR", issuer: "CN=AC Exemplo RFB, O=ICP-Brasil, C=BR", signed_at: now.toISOString() }, mandate, kyb, issuer, now });
  const credential = await signCredential(unsigned, priv, key.keyId, now);
  const q = { action: "pay", amount: 80, currency: "USDC", counterparty: "33000167000101" };
  const v = checkAction(mandate, q);
  const verdictBody: Record<string, unknown> = { credential_id: credential.credential_id, status: "active", allowed: v.allowed, reason: "inside the mandate", query: q, checks: v.checks, not_evaluated: v.not_evaluated, checked_at: now.toISOString() };
  const verdict = { ...verdictBody, attestation: await signAttestation(verdictBody, priv, key.keyId, `${issuer}/v1/verify`, now) };
  return {
    spec: "KYA Credential v1",
    generated_at: now.toISOString(),
    issuer_key: { key_id: key.keyId, jwk: key.publicJwk },
    challenge: { ...challenge, text: challengeText(challenge) },
    credential,
    verdict,
    tampered: { ...credential, mandate: { ...credential.mandate, max_per_operation: { amount: 50000, currency: "USDC" } } }
  };
}

describe("KYA Credential v1 test vectors", () => {
  it("docs/vectors/credential-v1.json verifies with the published key and the tampered copy does not", async () => {
    if (process.env.GEN_VECTORS) writeFileSync(FILE, JSON.stringify(await generate(), null, 2) + "\n");
    const v = JSON.parse(readFileSync(FILE, "utf8")) as Awaited<ReturnType<typeof generate>>;
    expect(v.credential.attestation?.key_id).toBe(v.issuer_key.key_id);
    expect((await verifyCredentialSignature(v.credential as Credential, v.issuer_key.jwk)).valid).toBe(true);
    expect((await verifyCredentialSignature(v.tampered as Credential, v.issuer_key.jwk)).valid).toBe(false);
    expect((await verifyAttestation(v.verdict as Record<string, unknown>, v.issuer_key.jwk)).valid).toBe(true);
    expect(v.challenge.text).toBe(challengeText(v.challenge));
    expect(v.challenge.text.split("\n")[0]).toBe("KYA Brasil: prove this agent key acts for a company");
    expect(checkAction(v.credential.mandate as Mandate, { action: "pay", amount: 80, currency: "USDC", counterparty: "33000167000101" }).allowed).toBe(true);
    expect(checkAction(v.credential.mandate as Mandate, { action: "pay", amount: 8000, currency: "USDC" }).allowed).toBe(false);
  });
});
