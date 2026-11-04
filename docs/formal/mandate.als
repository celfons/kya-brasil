/*
 * KYA Brasil: mandate, delegation and cascade, as an Alloy 6 model.
 *
 * It mirrors the reference implementation in @kya-brasil/core:
 *   allows[m, q]     <-> checkAction(m, q).allowed        (packages/core/src/mandate.ts, SPEC section 5)
 *   subset[p, c]     <-> isMandateSubset(p, c)             (packages/core/src/delegation.ts, SPEC section 17)
 *   permitted[...]   <-> checkFreshAction / the verifier's rule that a revoked credential ends every delegation
 * and states the properties that packages/core/src/properties.test.ts checks on random cases (P1 to P3).
 *
 * Abstractions, on purpose:
 *   - one per-operation ceiling (the daily ceiling follows the same rule with spent_today added);
 *   - counterparty wildcards ("*.domain") are plain set membership; the implementation's matching is checked
 *     by the property tests instead;
 *   - payment instruments and delegation depth/ttl are left out (same subset shape as currencies; depth and
 *     ttl only shorten chains);
 *   - time and amounts are small integers.
 *
 * Run with the Alloy 6 analyzer (https://alloytools.org): open this file and execute every command, or
 *   java -jar org.alloytools.alloy.dist.jar exec docs/formal/mandate.als
 * A "check" that finds no counterexample within its scope supports the property up to that scope; it is not
 * a proof for unbounded sizes.
 */
module kya/mandate

one sig Yes {}

sig Action {}
sig Currency {}
sig Party {}

sig Mandate {
  ra: lone Yes, acts: set Action,          -- restricts actions? which ones
  rc: lone Yes, curs: set Currency,        -- restricts currencies? which ones
  parties: set Party,                      -- counterparties; empty = any
  ceiling: lone Int, ceilCur: lone Currency,
  validFrom: lone Int, validUntil: lone Int
}

fact WellFormed {
  all m: Mandate {
    no m.ra implies no m.acts
    some m.ra implies some m.acts           -- validateMandate refuses an empty list
    no m.rc implies no m.curs
    some m.rc implies some m.curs
    some m.ceiling iff some m.ceilCur
    some m.ceiling implies m.ceiling > 0
    (some m.validFrom and some m.validUntil) implies m.validFrom < m.validUntil
  }
}

sig Query {
  act: lone Action,
  cur: lone Currency,
  party: lone Party,
  amount: lone Int,
  now: one Int
}

fact NonNegativeAmounts { all q: Query | some q.amount implies q.amount >= 0 }

/* checkAction: a rule is evaluated only when both the mandate and the query carry its field,
   except actions, which a restricted mandate requires. */
pred allowsFrom[m: Mandate, q: Query]    { some m.validFrom implies q.now >= m.validFrom }
pred allowsUntil[m: Mandate, q: Query]   { some m.validUntil implies q.now <= m.validUntil }
pred allowsAction[m: Mandate, q: Query]  { some m.ra implies (some q.act and q.act in m.acts) }
pred allowsCur[m: Mandate, q: Query]     { (some m.rc and some q.cur) implies q.cur in m.curs }
pred allowsCeiling[m: Mandate, q: Query] { (some m.ceiling and some q.amount) implies ((no q.cur or q.cur = m.ceilCur) and q.amount <= m.ceiling) }
pred allowsParty[m: Mandate, q: Query]   { (some m.parties and some q.party) implies q.party in m.parties }

pred allows[m: Mandate, q: Query] {
  allowsFrom[m, q] and allowsUntil[m, q] and allowsAction[m, q]
  allowsCur[m, q] and allowsCeiling[m, q] and allowsParty[m, q]
}

/* mandateSubsetProblems(p, c) is empty: every field the parent restricts, the child restricts at least as much. */
pred subActs[p, c: Mandate]    { some p.ra implies (some c.ra and c.acts in p.acts) }
pred subCurs[p, c: Mandate]    { some p.rc implies (some c.rc and c.curs in p.curs) }
pred subCeiling[p, c: Mandate] { some p.ceiling implies (some c.ceiling and c.ceilCur = p.ceilCur and c.ceiling <= p.ceiling) }
pred subParties[p, c: Mandate] { some p.parties implies (some c.parties and c.parties in p.parties) }
pred subFrom[p, c: Mandate]    { some p.validFrom implies (some c.validFrom and c.validFrom >= p.validFrom) }
pred subUntil[p, c: Mandate]   { some p.validUntil implies (some c.validUntil and c.validUntil <= p.validUntil) }

pred subset[p, c: Mandate] {
  subActs[p, c] and subCurs[p, c] and subCeiling[p, c]
  subParties[p, c] and subFrom[p, c] and subUntil[p, c]
}

/* A credential and a chain of delegated mandates; an action passes only when the credential is in force and
   every mandate in the chain allows it (SPEC section 17, checkDelegatedAction; section 18, checkFreshAction). */
sig Credential { signed: one Mandate, inForce: lone Yes }

pred chainOk[cr: Credential, chain: seq Mandate] {
  some chain
  chain.first = cr.signed
  all i: chain.inds - chain.lastIdx | subset[chain[i], chain[i.add[1]]]
}

pred permitted[cr: Credential, chain: seq Mandate, q: Query] {
  some cr.inForce
  chainOk[cr, chain]
  all m: chain.elems | allows[m, q]
}

-- P1, one level: a contained delegated mandate never allows what its parent refuses.
assert NonAmplification { all p, c: Mandate, q: Query | (subset[p, c] and allows[c, q]) implies allows[p, q] }
check NonAmplification for 5 but 5 Int

-- P1, chains: containment composes, so the end of a valid chain never exceeds the signed mandate.
assert SubsetTransitive { all a, b, c: Mandate | (subset[a, b] and subset[b, c]) implies subset[a, c] }
check SubsetTransitive for 5 but 5 Int

assert ChainNonAmplification {
  all cr: Credential, chain: seq Mandate, q: Query |
    (chainOk[cr, chain] and allows[chain.last, q]) implies allows[cr.signed, q]
}
check ChainNonAmplification for 4 but 5 Int, 4 seq

-- P3: a credential not in force permits nothing, whatever its chain allows.
assert Cascade { all cr: Credential, chain: seq Mandate, q: Query | no cr.inForce implies not permitted[cr, chain, q] }
check Cascade for 4 but 5 Int, 4 seq

-- Sanity: the model is not vacuous; there are proper delegations and permitted actions.
run ProperDelegation { some cr: Credential, chain: seq Mandate, q: Query | #chain = 3 and chain[1] != chain[0] and permitted[cr, chain, q] } for 4 but 5 Int, 4 seq
