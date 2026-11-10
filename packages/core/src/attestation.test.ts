import { describe, expect, it } from "vitest";
import { canonicalEquals, canonicalize } from "./attestation.js";
import { verifyMandateAuthorization } from "./credential.js";
import type { Credential } from "./types.js";

describe("canonical JSON key order", () => {
  it("is UTF-16 code-unit order, the same as a comparator-less sort (signed bytes must not change)", () => {
    const keys = ["b", "a", "B", "é", "_", "Z", "aa", "10", "9", "ação", "acao"];
    const o = Object.fromEntries(keys.map((k, i) => [k, i]));
    const legacy = `{${[...keys].sort().map((k) => `${JSON.stringify(k)}:${o[k]}`).join(",")}}`; // NOSONAR: the reference order
    expect(canonicalize(o)).toBe(legacy);
    expect(canonicalize({ z: { b: 1, a: [{ d: 1, c: 2 }] }, a: null })).toBe('{"a":null,"z":{"a":[{"c":2,"d":1}],"b":1}}');
  });
});

/** The samples of RFC 8785 itself (sections 3.2.2 to 3.2.4 and Appendix B), copied from the RFC text. */
describe("canonical JSON is RFC 8785 (JCS)", () => {
  const sample = String.raw`{
    "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
    "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
    "literals": [null, true, false]
  }`;

  it("serializes the sample of section 3.2.2 as section 3.2.3 says", () => {
    const expected = String.raw`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`;
    expect(canonicalize(JSON.parse(sample))).toBe(expected);
  });

  it("gives the UTF-8 bytes of section 3.2.4", () => {
    const expectedHex =
      "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62657273223a" +
      "5b3333333333333333332e333333333333332c31652b33302c342e352c302e3030322c31652d3237" +
      "5d2c22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d";
    const bytes = new TextEncoder().encode(canonicalize(JSON.parse(sample)));
    expect([...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")).toBe(expectedHex);
  });

  it("sorts member names by UTF-16 code units (section 3.2.3)", () => {
    const input = String.raw`{
      "\u20ac": "Euro Sign",
      "\r": "Carriage Return",
      "\ufb33": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "\ud83d\ude00": "Emoji: Grinning Face",
      "\u0080": "Control",
      "\u00f6": "Latin Small Letter O With Diaeresis"
    }`;
    const values = [...canonicalize(JSON.parse(input)).matchAll(/:"([^"]*)"/g)].map((m) => m[1]);
    expect(values).toEqual([
      "Carriage Return",
      "One",
      "Control",
      "Latin Small Letter O With Diaeresis",
      "Euro Sign",
      "Emoji: Grinning Face",
      "Hebrew Letter Dalet With Dagesh"
    ]);
  });

  it("serializes the numbers of Appendix B", () => {
    const table: [string, string][] = [
      ["0000000000000000", "0"],
      ["8000000000000000", "0"],
      ["0000000000000001", "5e-324"],
      ["8000000000000001", "-5e-324"],
      ["7fefffffffffffff", "1.7976931348623157e+308"],
      ["ffefffffffffffff", "-1.7976931348623157e+308"],
      ["4340000000000000", "9007199254740992"],
      ["c340000000000000", "-9007199254740992"],
      ["4430000000000000", "295147905179352830000"],
      ["44b52d02c7e14af5", "9.999999999999997e+22"],
      ["44b52d02c7e14af6", "1e+23"],
      ["44b52d02c7e14af7", "1.0000000000000001e+23"],
      ["444b1ae4d6e2ef4e", "999999999999999700000"],
      ["444b1ae4d6e2ef4f", "999999999999999900000"],
      ["444b1ae4d6e2ef50", "1e+21"],
      ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
      ["3eb0c6f7a0b5ed8d", "0.000001"],
      ["41b3de4355555553", "333333333.3333332"],
      ["41b3de4355555554", "333333333.33333325"],
      ["41b3de4355555555", "333333333.3333333"],
      ["41b3de4355555556", "333333333.3333334"],
      ["41b3de4355555557", "333333333.33333343"],
      ["becbf647612f3696", "-0.0000033333333333333333"],
      ["43143ff3c1cb0959", "1424953923781206.2"]
    ];
    const fromIeee = (hex: string) => {
      const view = new DataView(new ArrayBuffer(8));
      view.setBigUint64(0, BigInt(`0x${hex}`));
      return view.getFloat64(0);
    };
    for (const [ieee, json] of table) expect(canonicalize(fromIeee(ieee)), ieee).toBe(json);
  });

  it("refuses what is not JSON data instead of guessing", () => {
    for (const bad of [NaN, Infinity, -Infinity]) {
      expect(() => canonicalize({ amount: bad })).toThrow(/RFC 8785.*not finite/);
    }
    expect(() => canonicalize({ name: "\ud800" })).toThrow(/lone surrogate/);
    expect(() => canonicalize({ name: "a\udc00b" })).toThrow(/lone surrogate/);
    expect(() => canonicalize({ ["k\udead"]: 1 })).toThrow(/lone surrogate/);
    expect(() => canonicalize([1, undefined, 2])).toThrow(/not JSON/);
    expect(() => canonicalize([1, , 2])).toThrow(/not JSON/); // NOSONAR: a sparse array on purpose
    expect(() => canonicalize({ n: 10n })).toThrow(/not JSON/);
    expect(canonicalize({ a: 1, gone: undefined })).toBe('{"a":1}');
    expect(canonicalize({ smile: "\ud83d\ude00" })).toBe(JSON.stringify({ smile: String.fromCodePoint(0x1f600) }));
  });

  it("canonicalEquals answers false, never throws", () => {
    expect(canonicalEquals({ b: 1, a: 2 }, { a: 2, b: 1 })).toBe(true);
    expect(canonicalEquals({ a: 1 }, { a: 2 })).toBe(false);
    expect(canonicalEquals({ a: NaN }, { a: NaN })).toBe(false);
  });

  it("a mandate that is not JSON data is a mismatch in verification, not an exception", async () => {
    const c = { mandate: { max_per_operation: { amount: NaN, currency: "BRL" } }, authorized_by: { mandate_sha256: "0".repeat(64) } };
    expect(await verifyMandateAuthorization(c as unknown as Pick<Credential, "mandate" | "authorized_by">)).toBe("mismatch");
  });
});
