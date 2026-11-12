// The CNPJ helpers had no test of their own: mutation testing (research/mutation) showed whole functions that no
// test reached, and check-digit edges that could be moved.
import { describe, expect, it } from "vitest";
import { cnpjRoot, formatCnpj, isHeadquarters, isValidCnpj, normalizeCnpj } from "./cnpj.js";

describe("CNPJ", () => {
  it("accepts a valid CNPJ, numeric or alphanumeric, with or without punctuation", () => {
    for (const v of ["11222333000181", "11.222.333/0001-81", " 11 222 333 0001 81 ", "12ABC34501DE35", "12.abc.345/01de-35"]) expect(isValidCnpj(v), v).toBe(true);
  });

  it("computes each check digit at the edges of the rule: remainder 0, 1 and 2", () => {
    // Remainders 0 and 1 give the digit 0; remainder 2 gives 9. First digit, then second.
    for (const v of ["00000007000103", "00000009000100", "00000018000193", "00000002000180", "00000004000170", "00000006000169"]) expect(isValidCnpj(v), v).toBe(true);
    // The same bases with the other digit of each edge are refused.
    for (const v of ["00000007000193", "00000018000103", "00000002000189", "00000006000160"]) expect(isValidCnpj(v), v).toBe(false);
  });

  it("refuses a wrong check digit, a wrong length, a letter among the check digits and a repeated character", () => {
    for (const v of ["11222333000182", "11222333000191", "11222333000180", "1122233300018", "112223330001810", "011222333000181", "112223330001AB", "1122233300018A", "", "00000000000000", "11111111111111", "AAAAAAAAAAAAAA"]) expect(isValidCnpj(v), v).toBe(false);
  });

  it("normalizes, formats, and reads the root and the branch", () => {
    expect(normalizeCnpj(" 12.abc.345/01de-35 ")).toBe("12ABC34501DE35");
    expect(formatCnpj("11222333000181")).toBe("11.222.333/0001-81");
    expect(formatCnpj("12abc34501de35")).toBe("12.ABC.345/01DE-35");
    for (const v of ["1122233300018", "112223330001810", ""]) expect(() => formatCnpj(v)).toThrow(`Invalid CNPJ length: ${v.length}`);
    expect(cnpjRoot("11.222.333/0001-81")).toBe("11222333");
    expect(cnpjRoot("12.abc.345/01de-35")).toBe("12ABC345");
    expect(isHeadquarters("11.222.333/0001-81")).toBe(true);
    expect(isHeadquarters("11.222.333/0002-62")).toBe(false);
    expect(isHeadquarters("12ABC34501DE35")).toBe(false);
  });
});
