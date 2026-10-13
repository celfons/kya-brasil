import { describe, expect, it } from "vitest";
import { canonicalize } from "./attestation";

describe("canonical JSON key order", () => {
  it("is UTF-16 code-unit order, the same as a comparator-less sort (signed bytes must not change)", () => {
    const keys = ["b", "a", "B", "é", "_", "Z", "aa", "10", "9", "ação", "acao"];
    const o = Object.fromEntries(keys.map((k, i) => [k, i]));
    const legacy = `{${[...keys].sort().map((k) => `${JSON.stringify(k)}:${o[k]}`).join(",")}}`; // NOSONAR: the reference order
    expect(canonicalize(o)).toBe(legacy);
    expect(canonicalize({ z: { b: 1, a: [{ d: 1, c: 2 }] }, a: null })).toBe('{"a":null,"z":{"a":[{"c":2,"d":1}],"b":1}}');
  });
});
