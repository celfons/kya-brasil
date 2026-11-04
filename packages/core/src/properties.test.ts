/**
 * Property-based tests of the model's properties (SPEC sections 5, 17 and 18), on randomly generated mandates,
 * delegation chains, actions and evidence. A seeded generator keeps every run identical; a failure prints the
 * seed and the case. The same properties are stated in docs/formal/mandate.als and checked there by Alloy.
 *
 *   P1 non-amplification: if a delegated mandate is contained in its parent, every action it allows, the
 *      parent allows too; along a chain, every action allowed at the end is allowed by the signed mandate.
 *   P2 determinism: the same mandate, action and clock give the same verdict.
 *   P3 cascade: when the credential is not in force, no action passes, whatever the chain allows.
 *   P4 bounded exposure: under the formula policy, an accepted action's expected loss v × λ × age is at most L.
 */
import { describe, expect, it } from "vitest";
import { type StatusEvidence, checkFreshAction, checkFreshness, freshnessPolicy } from "./freshness.js";
import { checkDelegatedAction, isMandateSubset } from "./delegation.js";
import { type ActionQuery, checkAction, validateMandate } from "./mandate.js";
import type { Mandate } from "./types.js";

const RUNS = 3000;
const SEED = 20261104;

function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)]!;
  const some = <T>(xs: readonly T[]): T[] => xs.filter(() => next() < 0.5);
  /** A random non-empty subset. */
  const several = <T>(xs: readonly T[]): T[] => {
    const s = some(xs);
    return s.length ? s : [pick(xs)];
  };
  return { next, int, pick, some, several, chance: (p: number) => next() < p };
}
type R = ReturnType<typeof rng>;

const ACTIONS = ["buy", "sell", "quote", "pay", "sign"] as const;
const CURRENCIES = ["BRL", "USD", "USDC"] as const;
const PARTIES = ["12345678000190", "98765432000110", "beta.com.br", "x.beta.com.br", "*.beta.com.br", "gamma.io"] as const;
const AMOUNTS = [10, 100, 500, 1000, 5000, 20000] as const;
const DAYS = ["2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", "2026-11-04T12:00:00Z", "2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z"] as const;
const REF = (n: number) => n.toString(16).padStart(64, "0");
const INSTRUMENTS = [{ network: "visa", ref_sha256: REF(1) }, { network: "visa", ref_sha256: REF(2) }, { network: "pix", ref_sha256: REF(3) }] as const;

function randomMandate(r: R): Mandate {
  const m: Record<string, unknown> = {};
  if (r.chance(0.8)) m.actions = r.several(ACTIONS);
  if (r.chance(0.6)) m.max_per_operation = { amount: r.pick(AMOUNTS), currency: r.pick(CURRENCIES) };
  if (r.chance(0.4)) m.max_per_day = { amount: r.pick(AMOUNTS) * 4, currency: r.pick(CURRENCIES) };
  if (r.chance(0.5)) m.currencies = r.several(CURRENCIES);
  if (r.chance(0.5)) m.counterparties = r.some(PARTIES);
  if (r.chance(0.3)) m.payment_instruments = r.some(INSTRUMENTS).map((i) => ({ ...i }));
  const from = r.chance(0.4) ? r.int(2) : null;
  const until = r.chance(0.4) ? 2 + r.int(3) : null; // always after any valid_from
  if (from !== null) m.valid_from = DAYS[from];
  if (until !== null) m.valid_until = DAYS[until];
  if (r.chance(0.5)) m.delegation = { max_depth: 1 + r.int(3), max_ttl_seconds: 60 * (1 + r.int(60)) };
  return validateMandate(m);
}

/** A child built by narrowing the parent, so that a good share of them are contained in it. */
function narrowed(r: R, parent: Mandate): Mandate {
  if (r.chance(0.25)) return randomMandate(r); // also try unrelated mandates: most are not contained
  const m: Record<string, unknown> = {};
  if (parent.actions) m.actions = r.several(parent.actions);
  else if (r.chance(0.5)) m.actions = [r.pick(ACTIONS)];
  for (const k of ["max_per_operation", "max_per_day"] as const) {
    const p = parent[k];
    if (p) m[k] = { amount: r.chance(0.8) ? p.amount : p.amount * 2, currency: r.chance(0.9) ? p.currency : r.pick(CURRENCIES) };
  }
  if (parent.currencies) m.currencies = r.several(parent.currencies);
  if (parent.counterparties?.length) m.counterparties = r.several(parent.counterparties);
  if (parent.payment_instruments?.length) m.payment_instruments = [parent.payment_instruments[0]!];
  if (parent.valid_from) m.valid_from = parent.valid_from;
  if (parent.valid_until) m.valid_until = parent.valid_until;
  if (parent.delegation && parent.delegation.max_depth > 1 && r.chance(0.5)) m.delegation = { max_depth: parent.delegation.max_depth - 1, max_ttl_seconds: parent.delegation.max_ttl_seconds };
  return validateMandate(m);
}

function randomQuery(r: R): ActionQuery {
  const q: ActionQuery = { now: new Date(DAYS[r.int(DAYS.length)]!) };
  if (r.chance(0.9)) q.action = r.pick(ACTIONS);
  if (r.chance(0.8)) q.amount = r.pick(AMOUNTS) * (r.chance(0.5) ? 1 : 0.5);
  if (r.chance(0.7)) q.currency = r.pick(CURRENCIES);
  if (r.chance(0.6)) q.counterparty = r.pick(["12345678000190", "beta.com.br", "y.beta.com.br", "x.beta.com.br", "gamma.io", "delta.org"]);
  if (r.chance(0.4)) q.spent_today = r.pick(AMOUNTS);
  if (r.chance(0.3)) {
    const i = r.pick(INSTRUMENTS);
    q.payment_ref_sha256 = i.ref_sha256;
    if (r.chance(0.5)) q.payment_network = i.network;
  }
  return q;
}

const describeCase = (seed: number, i: number, data: unknown) => `seed ${seed}, case ${i}: ${JSON.stringify(data)}`;

describe("P1 non-amplification", () => {
  it("a contained delegated mandate never allows what its parent refuses", () => {
    const r = rng(SEED);
    let contained = 0;
    for (let i = 0; i < RUNS; i++) {
      const parent = randomMandate(r);
      const child = narrowed(r, parent);
      if (!isMandateSubset(parent, child)) continue;
      contained++;
      for (let k = 0; k < 8; k++) {
        const q = randomQuery(r);
        if (checkAction(child, q).allowed) expect(checkAction(parent, q).allowed, describeCase(SEED, i, { parent, child, q })).toBe(true);
      }
    }
    expect(contained).toBeGreaterThan(RUNS / 4); // the generator must exercise the property, not skip it
  });

  it("along a chain of contained mandates, the end never allows what the signed mandate refuses", () => {
    const r = rng(SEED + 1);
    let chains = 0;
    for (let i = 0; i < RUNS; i++) {
      const chain: Mandate[] = [randomMandate(r)];
      for (let depth = 0; depth < 3; depth++) {
        const next = narrowed(r, chain.at(-1)!);
        if (!isMandateSubset(chain.at(-1)!, next)) break;
        chain.push(next);
      }
      if (chain.length < 2) continue;
      chains++;
      const q = randomQuery(r);
      if (checkAction(chain.at(-1)!, q).allowed) expect(checkAction(chain[0]!, q).allowed, describeCase(SEED + 1, i, { chain, q })).toBe(true);
      if (checkDelegatedAction(chain, q).allowed) expect(checkAction(chain[0]!, q).allowed).toBe(true);
    }
    expect(chains).toBeGreaterThan(RUNS / 4);
  });
});

describe("P2 determinism", () => {
  it("the same mandate, action and clock give the same verdict, also after a JSON round trip", () => {
    const r = rng(SEED + 2);
    for (let i = 0; i < RUNS; i++) {
      const m = randomMandate(r);
      const q = randomQuery(r);
      const a = checkAction(m, q);
      const b = checkAction(validateMandate(JSON.parse(JSON.stringify(m))), { ...q });
      expect(b, describeCase(SEED + 2, i, { m, q })).toEqual(a);
    }
  });
});

const NOW = new Date("2026-11-04T12:00:00Z");
const BASE = { max_expected_loss: { amount: 1, currency: "BRL" }, revocation_rate_per_hour: { credential: 1e-4 }, require: ["credential" as const], max_age_seconds: 86_400, max_clock_skew_seconds: 300, unvalued_action: "refuse" as const, past_valid_until: "refuse" as const };

describe("P3 cascade", () => {
  it("when the credential is not in force, no action passes, whatever the chain allows", () => {
    const r = rng(SEED + 3);
    const policy = freshnessPolicy(BASE);
    for (let i = 0; i < RUNS; i++) {
      const m = randomMandate(r);
      const q = { ...randomQuery(r), currency: "BRL", amount: r.pick(AMOUNTS), now: NOW };
      const revoked: StatusEvidence = { kind: "credential", in_force: false, as_of: new Date(NOW.getTime() - r.int(3600) * 1000).toISOString(), status: r.pick(["revoked", "suspended"]) };
      expect(checkFreshAction(m, q, { policy, evidence: [revoked] }).allowed, describeCase(SEED + 3, i, { m, q })).toBe(false);
    }
  });
});

describe("P4 bounded exposure", () => {
  it("an accepted action has v × λ × age at most L", () => {
    const r = rng(SEED + 4);
    for (let i = 0; i < RUNS; i++) {
      const L = r.pick([0.01, 0.1, 1, 10]);
      const lambda = r.pick([1e-6, 1e-5, 1e-4, 1e-3]);
      const policy = freshnessPolicy({ ...BASE, max_expected_loss: { amount: L, currency: "BRL" }, revocation_rate_per_hour: { credential: lambda }, max_age_seconds: 30 * 86_400 });
      const v = r.pick(AMOUNTS) * (0.5 + r.next());
      const ageSeconds = r.int(30 * 86_400);
      const evidence: StatusEvidence[] = [{ kind: "credential", in_force: true, as_of: new Date(NOW.getTime() - ageSeconds * 1000).toISOString() }];
      const verdict = checkFreshness(policy, evidence, { amount: v, currency: "BRL", now: NOW });
      if (verdict.ok) expect(v * lambda * (ageSeconds / 3600), describeCase(SEED + 4, i, { L, lambda, v, ageSeconds })).toBeLessThanOrEqual(L * (1 + 1e-9));
    }
  });
});
