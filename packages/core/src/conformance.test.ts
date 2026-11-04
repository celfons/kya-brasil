/// <reference types="node" /> // test-only: node:fs
/**
 * Conformance between the formal model (docs/formal/mandate.als) and the library: Alloy generates mandates
 * and actions with a known answer (docs/formal/conformance.als), docs/formal/generate-vectors.py writes them
 * to docs/vectors/mandate-conformance.json, and the library must give the same answer for every one.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { isMandateSubset } from "./delegation.js";
import { checkAction, validateMandate } from "./mandate.js";

interface Vector {
  command: string;
  solution: number;
  check: "subset" | "allows" | "delegated";
  expected: boolean;
  parent: Record<string, unknown>;
  child: Record<string, unknown>;
  query: { now: string; action?: string; currency?: string; counterparty?: string; amount?: number };
}

const FILE = new URL("../../../docs/vectors/mandate-conformance.json", import.meta.url);
const { vectors } = JSON.parse(readFileSync(FILE, "utf8")) as { vectors: Vector[] };

describe("conformance with the Alloy model", () => {
  it("has vectors for every kind of check, with both answers", () => {
    for (const [check, expected] of [["subset", true], ["subset", false], ["allows", true], ["allows", false], ["delegated", true]] as const) {
      expect(vectors.filter((v) => v.check === check && v.expected === expected).length, `${check}=${expected}`).toBeGreaterThan(50);
    }
  });

  it("gives the model's answer for every vector", () => {
    const mismatches: string[] = [];
    for (const v of vectors) {
      const parent = validateMandate(v.parent);
      const child = validateMandate(v.child);
      const q = { ...v.query, now: new Date(v.query.now) };
      const got =
        v.check === "subset" ? isMandateSubset(parent, child)
        : v.check === "allows" ? checkAction(child, q).allowed
        : isMandateSubset(parent, child) && checkAction(child, q).allowed && checkAction(parent, q).allowed;
      if (got !== v.expected) mismatches.push(`${v.command}#${v.solution}: expected ${v.expected}, library says ${got}: ${JSON.stringify(v)}`);
    }
    expect(mismatches).toEqual([]);
  });
});
