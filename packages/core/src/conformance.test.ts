/// <reference types="node" /> // test-only: node:fs
/**
 * Conformance between the formal model (docs/formal/mandate.als) and the library: Alloy generates mandates
 * and actions with a known answer (docs/formal/conformance.als), docs/formal/generate-vectors.py writes them
 * to docs/vectors/mandate-conformance.json, and the library must give the same answer for every one.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { isMandateSubset } from "./delegation.js";
import { type MandateTerms, buildDelegation } from "./issuance.js";
import { checkAction, validateMandate } from "./mandate.js";

interface Vector {
  command: string;
  solution: number;
  check: "subset" | "allows" | "delegated" | "issue";
  expected: boolean;
  parent: Record<string, unknown>;
  child: Record<string, unknown>;
  query: { now: string; action?: string; currency?: string; counterparty?: string; amount?: number };
}

const FILE = new URL("../../../docs/vectors/mandate-conformance.json", import.meta.url);
const { vectors } = JSON.parse(readFileSync(FILE, "utf8")) as { vectors: Vector[] };

const DELEGATOR = { kind: "evm" as const, id: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" };
const DELEGATE = { kind: "evm", id: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" };
const ISSUED_AT = new Date("2026-06-01T00:00:00Z");

/**
 * buildDelegation requires every risk field (D-37); the model leaves some out. A child is completed only where
 * that cannot change the answer: a list whose absence already means "any" or "none" in the library
 * (counterparties, payment_instruments, delegation), and a restriction that neither mandate sets (anything is
 * contained in an unrestricted parent). Where the parent restricts and the child does not, the field stays
 * missing: the model says "not contained" and issuance must refuse.
 */
function completeChild(parent: Record<string, unknown>, child: Record<string, unknown>): MandateTerms {
  const c: Record<string, unknown> = { ...child };
  c.counterparties ??= [];
  c.payment_instruments ??= [];
  c.delegation ??= null;
  const filler: Record<string, unknown> = { actions: ["act0"], max_per_operation: { amount: 1, currency: "CUR0" }, max_per_day: { amount: 1, currency: "CUR0" }, currencies: ["CUR0"], valid_from: "2026-01-01T00:00:00Z", valid_until: "2028-01-01T00:00:00Z" };
  for (const [k, v] of Object.entries(filler)) if (c[k] === undefined && parent[k] === undefined) c[k] = v;
  return c as MandateTerms;
}

async function issues(v: Vector): Promise<boolean> {
  const credential = { credential_id: "conformance", agent: DELEGATOR, mandate: validateMandate(v.parent), expires_at: "2030-01-01T00:00:00Z", status: "active" as const };
  try {
    await buildDelegation({ credential }, { delegate: DELEGATE, mandate: completeChild(v.parent, v.child), ttl_seconds: 600, now: ISSUED_AT });
    return true;
  } catch {
    return false;
  }
}

describe("conformance with the Alloy model", () => {
  it("has vectors for every kind of check, with both answers", () => {
    for (const [check, expected] of [["subset", true], ["subset", false], ["allows", true], ["allows", false], ["delegated", true], ["issue", true], ["issue", false]] as const) {
      expect(vectors.filter((v) => v.check === check && v.expected === expected).length, `${check}=${expected}`).toBeGreaterThan(50);
    }
  });

  it("gives the model's answer for every vector", async () => {
    const mismatches: string[] = [];
    for (const v of vectors) {
      const parent = validateMandate(v.parent);
      const child = validateMandate(v.child);
      const q = { ...v.query, now: new Date(v.query.now) };
      const got =
        v.check === "subset" ? isMandateSubset(parent, child)
        : v.check === "allows" ? checkAction(child, q).allowed
        : v.check === "issue" ? await issues(v)
        : isMandateSubset(parent, child) && checkAction(child, q).allowed && checkAction(parent, q).allowed;
      if (got !== v.expected) mismatches.push(`${v.command}#${v.solution}: expected ${v.expected}, library says ${got}: ${JSON.stringify(v)}`);
    }
    expect(mismatches).toEqual([]);
  });
});
