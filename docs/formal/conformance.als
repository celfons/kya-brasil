/*
 * Conformance instances for @kya-brasil/core: each command asks Alloy for mandates and an action with a
 * known answer under the model in mandate.als. generate-vectors.py turns the instances into
 * docs/vectors/mandate-conformance.json, and packages/core/src/conformance.test.ts checks that the library
 * gives the same answer for every one of them (isMandateSubset, checkAction, and since D-37 buildDelegation).
 *
 * Besides the overall yes/no cases, one command per rule breaks exactly that rule and keeps all the others,
 * so a defect in any single rule of the library shows up in its own vectors.
 */
open mandate

one sig P, C extends Mandate {}
one sig Q extends Query {}

run SubsetYes   { subset[P, C] }            for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run SubsetNo    { not subset[P, C] }        for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run AllowsYes   { allows[C, Q] }            for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run AllowsNo    { not allows[C, Q] }        for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
-- the property itself, from the implementation's side: C contained in P and allowing Q, so P must allow Q
run Delegated   { subset[P, C] and allows[C, Q] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential

-- exactly one subset rule broken
run SubsetNoActs     { not subActs[P, C]    and subCurs[P, C] and subCeiling[P, C] and subParties[P, C] and subFrom[P, C] and subUntil[P, C] and subDeleg[P, C] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run SubsetNoCurs     { not subCurs[P, C]    and subActs[P, C] and subCeiling[P, C] and subParties[P, C] and subFrom[P, C] and subUntil[P, C] and subDeleg[P, C] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run SubsetNoCeiling  { not subCeiling[P, C] and subActs[P, C] and subCurs[P, C] and subParties[P, C] and subFrom[P, C] and subUntil[P, C] and subDeleg[P, C] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run SubsetNoParties  { not subParties[P, C] and subActs[P, C] and subCurs[P, C] and subCeiling[P, C] and subFrom[P, C] and subUntil[P, C] and subDeleg[P, C] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run SubsetNoFrom     { not subFrom[P, C]    and subActs[P, C] and subCurs[P, C] and subCeiling[P, C] and subParties[P, C] and subUntil[P, C] and subDeleg[P, C] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run SubsetNoUntil    { not subUntil[P, C]   and subActs[P, C] and subCurs[P, C] and subCeiling[P, C] and subParties[P, C] and subFrom[P, C] and subDeleg[P, C] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run SubsetNoDeleg    { not subDeleg[P, C]   and subActs[P, C] and subCurs[P, C] and subCeiling[P, C] and subParties[P, C] and subFrom[P, C] and subUntil[P, C] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential

-- issuance (D-37): buildDelegation(P, C) must succeed exactly on these
run IssueYes          { issuable[P, C] }                       for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run IssueNo           { not issuable[P, C] }                   for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run IssueNoPermission { no P.deleg and subset[P, C] }          for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run IssueBroader      { some P.deleg and not subset[P, C] }    for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential

-- exactly one action rule broken
run AllowsNoFrom     { not allowsFrom[C, Q]    and allowsUntil[C, Q] and allowsAction[C, Q] and allowsCur[C, Q] and allowsCeiling[C, Q] and allowsParty[C, Q] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run AllowsNoUntil    { not allowsUntil[C, Q]   and allowsFrom[C, Q] and allowsAction[C, Q] and allowsCur[C, Q] and allowsCeiling[C, Q] and allowsParty[C, Q] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run AllowsNoAction   { not allowsAction[C, Q]  and allowsFrom[C, Q] and allowsUntil[C, Q] and allowsCur[C, Q] and allowsCeiling[C, Q] and allowsParty[C, Q] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run AllowsNoCur      { not allowsCur[C, Q]     and allowsFrom[C, Q] and allowsUntil[C, Q] and allowsAction[C, Q] and allowsCeiling[C, Q] and allowsParty[C, Q] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run AllowsNoCeiling  { not allowsCeiling[C, Q] and allowsFrom[C, Q] and allowsUntil[C, Q] and allowsAction[C, Q] and allowsCur[C, Q] and allowsParty[C, Q] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
run AllowsNoParty    { not allowsParty[C, Q]   and allowsFrom[C, Q] and allowsUntil[C, Q] and allowsAction[C, Q] and allowsCur[C, Q] and allowsCeiling[C, Q] } for 4 but 5 Int, exactly 2 Mandate, exactly 1 Query, 0 Credential
