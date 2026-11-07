/// <reference types="node" /> // test-only: node:fs
/**
 * Adversarial vectors (H4), freshness part: Alloy instances of docs/formal/adversarial.als over the threat model
 * (threats.als), written to docs/vectors/adversarial-v1.json by docs/formal/generate-adversarial.py. For each
 * vector, checkFreshness must accept exactly when the model's verifier accepts: CRL at most max_age old and the
 * certificate not listed on it. The residual window (revoked after thisUpdate) is accepted by both: the policy bounds
 * it, it does not remove it.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { type StatusEvidence, checkFreshness, freshnessPolicy } from "./freshness.js";

interface FreshVector {
  command: string;
  solution: number;
  source: "alloy" | "hand";
  kind: "freshness";
  this_update: number;
  now: number;
  revoked_at: number | null;
  max_age_seconds: number;
  expected_ok: boolean;
}

const FILE = new URL("../../../docs/vectors/adversarial-v1.json", import.meta.url);
const { vectors, epoch } = JSON.parse(readFileSync(FILE, "utf8")) as { vectors: ({ kind: string } & FreshVector)[]; epoch: string };
const fresh = vectors.filter((v): v is FreshVector => v.kind === "freshness");
const at = (s: number) => new Date(Date.parse(epoch) + s * 1000);

describe("adversarial vectors (H4): CRL freshness", () => {
  it("has vectors of every command", () => {
    const commands = new Set(fresh.map((v) => v.command));
    for (const c of ["FreshNotListed", "StaleNotListed", "FreshListed", "ResidualWindow", "AgeEdge", "StaleBySecond", "RevokedAtThisUpdate"]) expect(commands.has(c), c).toBe(true);
  });

  for (const v of fresh) {
    it(`${v.command} #${v.solution} (${v.source}): accepts=${v.expected_ok}`, () => {
      // A policy whose proportional limit never binds: the ceiling alone decides, as in the model (MAXAGE).
      const policy = freshnessPolicy({
        max_expected_loss: { amount: 1e12, currency: "BRL" },
        revocation_rate_per_hour: { certificate: 1e-12 },
        require: ["certificate"],
        max_age_seconds: v.max_age_seconds,
        max_clock_skew_seconds: 0,
        unvalued_action: "ceiling",
        past_valid_until: "refuse"
      });
      // The CRL lists the certificate iff it was revoked at or before thisUpdate (threats.als, listedIn).
      const listed = v.revoked_at !== null && v.revoked_at <= v.this_update;
      const evidence: StatusEvidence = { kind: "certificate", in_force: !listed, as_of: at(v.this_update).toISOString(), valid_until: null, source: "CRL (vector)", status: listed ? "revoked" : "not revoked" };
      const verdict = checkFreshness(policy, [evidence], { now: at(v.now) });
      expect(verdict.ok).toBe(v.expected_ok);
    });
  }
});
