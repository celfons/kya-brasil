import { describe, expect, it } from "vitest";
import { checkAction, validateMandate } from "./mandate";

describe("mandate", () => {
  it("normalizes reserved fields and keeps extensions", () => {
    const m = validateMandate({ actions: ["buy", "buy", "quote"], max_per_operation: { amount: 500, currency: "USDC" }, counterparties: ["33.000.167/0001-01", "0xB5A72BB9106975869165C380E52D157388346626", "Supplier.com"], custom_policy: { tier: 2 } });
    expect(m.actions).toEqual(["buy", "quote"]);
    expect(m.counterparties).toEqual(["33000167000101", "0xb5a72bb9106975869165c380e52d157388346626", "supplier.com"]);
    expect(m.custom_policy).toEqual({ tier: 2 });
  });

  it("rejects malformed reserved fields", () => {
    expect(() => validateMandate({ actions: ["Buy"] })).toThrow(/actions/);
    expect(() => validateMandate({ max_per_day: { amount: -1, currency: "BRL" } })).toThrow(/max_per_day/);
    expect(() => validateMandate({ valid_from: "2026-10-12T00:00:00Z", valid_until: "2026-10-01T00:00:00Z" })).toThrow(/valid_until/);
    expect(() => validateMandate([])).toThrow(/object/);
  });

  it("evaluates an action against the reserved rules and lists what it did not evaluate", () => {
    const m = validateMandate({ actions: ["pay"], max_per_operation: { amount: 100, currency: "USDC" }, max_per_day: { amount: 250, currency: "USDC" }, currencies: ["USDC"], counterparties: ["33000167000101"], valid_until: "2027-01-01T00:00:00Z", notes: "x" });
    const ok = checkAction(m, { action: "pay", amount: 80, currency: "USDC", counterparty: "33.000.167/0001-01", spent_today: 100, now: new Date("2026-10-12T00:00:00Z") });
    expect(ok.allowed).toBe(true);
    expect(ok.not_evaluated).toEqual(["notes"]);
    const tooMuch = checkAction(m, { action: "pay", amount: 80, currency: "USDC", counterparty: "33000167000101", spent_today: 200, now: new Date("2026-10-12T00:00:00Z") });
    expect(tooMuch.allowed).toBe(false);
    expect(tooMuch.checks.find((c) => c.rule === "max_per_day")?.ok).toBe(false);
    expect(checkAction(m, { action: "sell", now: new Date("2026-10-12T00:00:00Z") }).allowed).toBe(false);
    expect(checkAction(m, { action: "pay", now: new Date("2027-06-01T00:00:00Z") }).checks.find((c) => c.rule === "valid_until")?.ok).toBe(false);
  });
});
