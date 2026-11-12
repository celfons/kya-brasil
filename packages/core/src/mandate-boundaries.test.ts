// Boundaries of the mandate rules. Mutation testing (research/mutation) showed that these edges could be moved
// without any test failing: a ceiling met exactly, a limit of the schema, a field of the wrong type.
import { describe, expect, it } from "vitest";
import { KyaError } from "./types.js";
import { checkAction, counterpartyMatches, hashPaymentRef, normalizeCounterparty, validateDelegationPolicy, validateMandate } from "./mandate.js";

const HASH = "ab".repeat(32);
const refuses = (input: unknown, field: string) => {
  let thrown: unknown;
  try {
    validateMandate(input);
  } catch (e) {
    thrown = e;
  }
  expect(thrown, JSON.stringify(input)?.slice(0, 80)).toBeInstanceOf(KyaError);
  expect((thrown as KyaError).code).toBe("INVALID_INPUT");
  expect((thrown as KyaError).message).toContain(field);
};
const rule = (v: ReturnType<typeof checkAction>, name: string) => v.checks.find((c) => c.rule === name);

describe("validateMandate: what it refuses and the last value it accepts", () => {
  it("takes only a JSON object, up to 8192 bytes", () => {
    for (const v of [null, undefined, "pay", 5, [], [{ actions: ["pay"] }]]) refuses(v, "mandate must be a JSON object");
    const sized = (n: number) => {
      const empty = JSON.stringify({ note: "" }).length;
      return { note: "x".repeat(n - empty) };
    };
    expect(JSON.stringify(sized(8192))).toHaveLength(8192);
    expect(() => validateMandate(sized(8192))).not.toThrow();
    refuses(sized(8193), "larger than 8192 bytes");
  });

  it("actions: an array of up to 32 lowercase identifiers", () => {
    const names = (n: number) => Array.from({ length: n }, (_, i) => `act${i}`);
    expect(validateMandate({ actions: names(32) }).actions).toHaveLength(32);
    refuses({ actions: names(33) }, "actions");
    for (const v of ["pay", { 0: "pay" }, [5], ["pay", 5], ["Pay"], ["pay!"], ["!pay"], ["1pay"], ["p"], ["p".repeat(33)]]) refuses({ actions: v }, "actions");
    expect(validateMandate({ actions: ["pay", "pay", "quote"] }).actions).toEqual(["pay", "quote"]);
  });

  it("ceilings: an amount above zero, finite, and a currency, and nothing else", () => {
    for (const k of ["max_per_operation", "max_per_day"]) {
      for (const v of [null, 5, "5 BRL", [], { amount: 0, currency: "BRL" }, { amount: -1, currency: "BRL" }, { amount: Infinity, currency: "BRL" }, { amount: "5", currency: "BRL" }, { amount: 5 }, { amount: 5, currency: 986 }, { amount: 5, currency: "brl" }, { amount: 5, currency: "B" }, { amount: 5, currency: "BRL", per: "day" }]) {
        refuses({ [k]: v }, k);
      }
      expect(() => validateMandate({ [k]: { amount: 0.01, currency: "BRL" } })).not.toThrow();
    }
  });

  it("currencies: an array of up to 16 upper-case codes", () => {
    const codes = (n: number) => Array.from({ length: n }, (_, i) => `C${String(i).padStart(2, "0")}`);
    expect(() => validateMandate({ currencies: codes(16) })).not.toThrow();
    refuses({ currencies: codes(17) }, "currencies");
    for (const v of ["BRL", [986], ["brl"], ["BRL", null], ["B"], ["BRL "], ["x-BRL"]]) refuses({ currencies: v }, "currencies");
  });

  it("counterparties: an array of up to 200 strings of 1 to 128 characters", () => {
    const hosts = (n: number) => Array.from({ length: n }, (_, i) => `h${i}.example.com`);
    expect(validateMandate({ counterparties: hosts(200) }).counterparties).toHaveLength(200);
    refuses({ counterparties: hosts(201) }, "counterparties");
    for (const v of ["a.example.com", [5], ["a.example.com", null], [""], ["x".repeat(129)]]) refuses({ counterparties: v }, "counterparties");
    expect(() => validateMandate({ counterparties: ["x".repeat(128)] })).not.toThrow();
    expect(validateMandate({ counterparties: [" Shop.Example.COM "] }).counterparties).toEqual(["shop.example.com"]);
  });

  it("dates: ISO strings, and valid_until after valid_from", () => {
    for (const k of ["valid_from", "valid_until"]) for (const v of ["soon", 5, 1767225600000, true, {}]) refuses({ [k]: v }, k);
    refuses({ valid_from: "2026-11-01T00:00:00Z", valid_until: "2026-11-01T00:00:00Z" }, "valid_until");
    refuses({ valid_from: "2026-11-02T00:00:00Z", valid_until: "2026-11-01T00:00:00Z" }, "valid_until");
    expect(() => validateMandate({ valid_from: "2026-11-01T00:00:00Z", valid_until: "2026-11-01T00:00:01Z" })).not.toThrow();
    expect(() => validateMandate({ valid_from: "2026-11-01T00:00:00Z" })).not.toThrow();
    expect(() => validateMandate({ valid_until: "2026-11-01T00:00:00Z" })).not.toThrow();
  });

  it("delegation: depth 1 to 3 and lifetime 60 to 86400, integers, and no other field", () => {
    for (const v of [null, 5, "deep", [], [1, 60]]) refuses({ delegation: v }, "delegation");
    for (const v of [{ max_depth: 0, max_ttl_seconds: 600 }, { max_depth: 4, max_ttl_seconds: 600 }, { max_depth: 1.5, max_ttl_seconds: 600 }, { max_depth: "1", max_ttl_seconds: 600 }, { max_ttl_seconds: 600 }]) refuses({ delegation: v }, "max_depth");
    for (const v of [{ max_depth: 1, max_ttl_seconds: 59 }, { max_depth: 1, max_ttl_seconds: 86401 }, { max_depth: 1, max_ttl_seconds: 600.5 }, { max_depth: 1, max_ttl_seconds: "600" }, { max_depth: 1 }]) refuses({ delegation: v }, "max_ttl_seconds");
    refuses({ delegation: { max_depth: 1, max_ttl_seconds: 600, note: "x" } }, "unknown field(s): note");
    for (const d of [{ max_depth: 1, max_ttl_seconds: 60 }, { max_depth: 3, max_ttl_seconds: 86400 }]) expect(validateDelegationPolicy(d)).toEqual(d);
  });

  it("payment instruments: up to 20, a network name and the SHA-256 of the reference, never a card number", () => {
    const list = (n: number) => Array.from({ length: n }, (_, i) => ({ network: "visa", ref_sha256: String(i).padStart(2, "0").repeat(32) }));
    expect(validateMandate({ payment_instruments: list(20) }).payment_instruments).toHaveLength(20);
    refuses({ payment_instruments: list(21) }, "payment_instruments");
    for (const v of ["visa", { network: "visa", ref_sha256: HASH }, { length: 1 }]) refuses({ payment_instruments: v }, "payment_instruments");
    for (const v of [null, "visa", 5, ["visa", HASH]]) refuses({ payment_instruments: [v] }, "payment_instruments[0]");
    refuses({ payment_instruments: [{ network: "visa", ref_sha256: HASH, pan: "x" }] }, "unknown field(s): pan");
    for (const n of [5, null, "", "1visa", "visa!", "!visa", "v", "v".repeat(33), "vi sa"]) refuses({ payment_instruments: [{ network: n, ref_sha256: HASH }] }, "network");
    for (const h of [5, null, "", HASH.slice(1), HASH + "a", "x" + HASH, HASH + "x", "g".repeat(64), "4111111111111111"]) refuses({ payment_instruments: [{ network: "visa", ref_sha256: h }] }, "ref_sha256");
    for (const l of [5, null, "x".repeat(65), "card 4111 1111 1111", "4111.1111-1111 1111"]) refuses({ payment_instruments: [{ network: "visa", ref_sha256: HASH, label: l }] }, "label");
    expect(validateMandate({ payment_instruments: [{ network: " Visa ", ref_sha256: ` ${HASH.toUpperCase()} `, label: "x".repeat(64) }] }).payment_instruments).toEqual([{ network: "visa", ref_sha256: HASH, label: "x".repeat(64) }]);
    expect(() => validateMandate({ payment_instruments: [{ network: "visa", ref_sha256: HASH, label: "ends 4111 1111 111" }] })).not.toThrow();
    refuses({ payment_instruments: [{ network: "visa", ref_sha256: HASH }, { network: "VISA", ref_sha256: HASH.toUpperCase() }] }, "duplicate instrument");
    expect(validateMandate({ payment_instruments: [{ network: "visa", ref_sha256: HASH }, { network: "elo", ref_sha256: HASH }] }).payment_instruments).toHaveLength(2);
  });
});

describe("counterparties and payment references", () => {
  it("normalizes a CNPJ to its 14 characters in upper case and anything else to lower case", () => {
    expect(normalizeCounterparty(" 12.345.678/0001-90 ")).toBe("12345678000190");
    expect(normalizeCounterparty("12.abc.345/01de-35")).toBe("12ABC34501DE35");
    expect(normalizeCounterparty("ABCDEFGHIJKLMN")).toBe("abcdefghijklmn"); // 14 characters, not a CNPJ
    expect(normalizeCounterparty("Loja.Example.com")).toBe("loja.example.com");
    expect(normalizeCounterparty(" 0xABCDEFabcdef0123456789ABCDEFabcdef012345 ")).toBe("0xabcdefabcdef0123456789abcdefabcdef012345");
  });

  it("matches a wildcard entry on the domain and its subdomains, and any other entry only exactly", () => {
    expect(counterpartyMatches("*.beta.com.br", "beta.com.br")).toBe(true);
    expect(counterpartyMatches("*.beta.com.br", "shop.beta.com.br")).toBe(true);
    expect(counterpartyMatches("*.beta.com.br", "xbeta.com.br")).toBe(false);
    expect(counterpartyMatches("*.beta.com.br", "beta.com.br.evil.com")).toBe(false);
    expect(counterpartyMatches("beta.com.br", "shop.beta.com.br")).toBe(false);
    // Without the "*." the first two characters are part of the name, not a wildcard.
    expect(counterpartyMatches("xxbeta.com.br", "beta.com.br")).toBe(false);
    expect(counterpartyMatches("x.beta.com.br", "y.beta.com.br")).toBe(false);
    expect(counterpartyMatches(" Beta.com.br ", "beta.com.br")).toBe(true);
  });

  it("hashes a payment reference without its whitespace and refuses an empty one", async () => {
    expect(await hashPaymentRef("tok 123\t456\n")).toBe(await hashPaymentRef("tok123456"));
    expect(await hashPaymentRef("tok123456")).toMatch(/^[0-9a-f]{64}$/);
    expect(await hashPaymentRef("Tok")).not.toBe(await hashPaymentRef("tok"));
    await expect(hashPaymentRef(" \n\t ")).rejects.toThrow(/empty payment reference/);
    await expect(hashPaymentRef("")).rejects.toThrow(KyaError);
  });
});

describe("checkAction at the edge of each rule", () => {
  const now = new Date("2026-11-04T12:00:00Z");

  it("allows an amount equal to the ceiling and refuses the next cent", () => {
    const m = validateMandate({ max_per_operation: { amount: 5000, currency: "BRL" }, max_per_day: { amount: 20000, currency: "BRL" } });
    expect(checkAction(m, { amount: 5000, currency: "BRL", now }).allowed).toBe(true);
    const over = checkAction(m, { amount: 5000.01, currency: "BRL", now });
    expect(over.allowed).toBe(false);
    expect(rule(over, "max_per_operation")?.ok).toBe(false);
    expect(rule(over, "max_per_day")?.ok).toBe(true);
    expect(checkAction(m, { amount: 5000, spent_today: 15000, currency: "BRL", now }).allowed).toBe(true);
    const day = checkAction(m, { amount: 5000, spent_today: 15000.01, currency: "BRL", now });
    expect(day.allowed).toBe(false);
    expect(rule(day, "max_per_operation")?.ok).toBe(true);
    expect(rule(day, "max_per_day")?.ok).toBe(false);
  });

  it("refuses an amount in a currency other than the ceiling's, per operation and per day", () => {
    const perOperation = checkAction(validateMandate({ max_per_operation: { amount: 5000, currency: "BRL" } }), { amount: 1, currency: "USD", now });
    expect(rule(perOperation, "max_per_operation")).toMatchObject({ ok: false, detail: "ceiling is in BRL, operation in USD" });
    const perDay = checkAction(validateMandate({ max_per_day: { amount: 5000, currency: "BRL" } }), { amount: 1, currency: "USD", now });
    expect(rule(perDay, "max_per_day")).toMatchObject({ ok: false, detail: "ceiling is in BRL, operation in USD" });
    expect(perDay.allowed).toBe(false);
    // The currency is compared without regard to case, and an amount with no currency is taken in the ceiling's.
    for (const m of [validateMandate({ max_per_operation: { amount: 5000, currency: "BRL" } }), validateMandate({ max_per_day: { amount: 5000, currency: "BRL" } })]) {
      expect(checkAction(m, { amount: 1, currency: "brl", now }).allowed).toBe(true);
      expect(checkAction(m, { amount: 1, now }).allowed).toBe(true);
      expect(checkAction(m, { amount: 5001, now }).allowed).toBe(false);
    }
  });

  it("evaluates a ceiling only when the action has an amount", () => {
    const v = checkAction(validateMandate({ max_per_operation: { amount: 5000, currency: "BRL" }, max_per_day: { amount: 20000, currency: "BRL" } }), { action: "quote", now });
    expect(v.checks).toEqual([]);
    expect(v.allowed).toBe(true);
  });

  it("compares the currency of the action in upper case", () => {
    const m = validateMandate({ currencies: ["BRL"] });
    expect(rule(checkAction(m, { currency: "brl", now }), "currencies")).toMatchObject({ ok: true, detail: "currency BRL allowed [BRL]" });
    expect(rule(checkAction(m, { currency: "usd", now }), "currencies")).toMatchObject({ ok: false, detail: "currency USD not in [BRL]" });
  });

  it("includes the first and the last instant of the window", () => {
    const m = validateMandate({ valid_from: "2026-11-01T00:00:00Z", valid_until: "2026-12-01T00:00:00Z" });
    expect(checkAction(m, { now: new Date("2026-11-01T00:00:00Z") }).allowed).toBe(true);
    expect(checkAction(m, { now: new Date("2026-10-31T23:59:59.999Z") }).allowed).toBe(false);
    expect(checkAction(m, { now: new Date("2026-12-01T00:00:00Z") }).allowed).toBe(true);
    expect(checkAction(m, { now: new Date("2026-12-01T00:00:00.001Z") }).allowed).toBe(false);
  });

  it("finds a payment instrument by the hash as given, in any case and with spaces, within the network asked", () => {
    const m = validateMandate({ payment_instruments: [{ network: "visa", ref_sha256: HASH, label: "corporate" }] });
    const hit = checkAction(m, { payment_ref_sha256: ` ${HASH.toUpperCase()} `, payment_network: " VISA ", now });
    expect(rule(hit, "payment_instruments")).toMatchObject({ ok: true, detail: `visa instrument ${HASH.slice(0, 12)}… is authorized (corporate)` });
    expect(checkAction(m, { payment_ref_sha256: HASH, now }).allowed).toBe(true);
    const otherNetwork = checkAction(m, { payment_ref_sha256: HASH, payment_network: "elo", now });
    expect(rule(otherNetwork, "payment_instruments")).toMatchObject({ ok: false, detail: `instrument elo ${HASH.slice(0, 12)}… is not in the mandate` });
    const otherHash = checkAction(m, { payment_ref_sha256: "cd".repeat(32), now });
    expect(rule(otherHash, "payment_instruments")).toMatchObject({ ok: false, detail: `instrument ${"cd".repeat(6)}… is not in the mandate` });
  });

  it("lists the fields it does not evaluate, and delegation is not one of them", () => {
    const v = checkAction(validateMandate({ actions: ["pay"], delegation: { max_depth: 1, max_ttl_seconds: 60 }, cost_center: "TI" }), { action: "pay", now });
    expect(v.not_evaluated).toEqual(["cost_center"]);
  });
});
