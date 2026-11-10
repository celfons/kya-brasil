module representative

/* ------------------------------------------------------------------------------------------------------------
 * Company mandate signed by a legal representative alone (SPEC section 22, D-43).
 *
 * Resolução CG ICP-Brasil 211/2024 ends the company's signature certificate on 2 March 2029. From then on a legal
 * person holds only an electronic seal, which attests origin and integrity and may not express its will (art. 4;
 * DOC-ICP-04, item 1.4.2.2), and signature certificates belong to natural persons. The mandate of a company is then
 * signed by a representative's e-CPF, with no e-CNPJ. The e-CPF says who signed, not whom that person represents:
 * the verifier supplies representatives(cnpj) -> cpf[] and accepts only when the signer's CPF is in that list.
 *
 * A separate module, with its own signatures, so that threats.als and the vectors generated from it stay as they
 * are. People and CPFs are separate, as there: the list holds CPFs, a certificate names a CPF or a company and is
 * held (operated) by some person.
 *
 *   java -jar org.alloytools.alloy.dist.jar exec -f -o out-representative docs/formal/representative.als
 * ---------------------------------------------------------------------------------------------------------- */

sig Cpf {}
sig Human { cpf: one Cpf }
fact CpfIsUnique { all disj h1, h2: Human | h1.cpf != h2.cpf }

/* Truth: who really represents the company today. Verifier: the CPF list it was given for that company. */
sig Firm { realReps: set Human, listed: set Cpf }

sig Text {}
abstract sig Cert { operator: one Human }
sig ECpf extends Cert { owner: one Cpf }   -- a natural person's signature certificate
sig Seal extends Cert { of: one Firm }     -- the company's electronic seal (SE-S or SE-H)

/* A company mandate: one CMS by `signer` over `signedText`; `challenge` is the text the mandate requires. */
sig Mandate { firm: one Firm, signer: one Cert, challenge: one Text, signedText: one Text }

/* One verification: the mandate presented, and whether the verifier has a list of representatives at all. */
one sig Yes {}
sig Attempt { m: one Mandate, hasList: lone Yes }

/* The verifier's rule as implemented (verifyPrincipalProof, rule "representative"; checkCms refuses a seal). */
pred accepted[a: Attempt] {
  some a.hasList
  a.m.signer in ECpf
  a.m.signedText = a.m.challenge
  a.m.signer.owner in a.m.firm.listed
}

/* What we want: a real representative, in person, agreed to THIS mandate. */
pred companyWillOf[x: Mandate] { x.signedText = x.challenge and x.signer.operator in x.firm.realReps }

/* Assumptions the design rests on: the same two as the co-signature in threats.als. */
pred listIsAccurate { all f: Firm | f.listed in f.realReps.cpf }
pred eCpfHeldByOwner { all c: ECpf | c.operator.cpf = c.owner }

-- Expected to hold: accurate list and e-CPFs operated by their owners => accepted implies the company's will.
assert RepresentativeSound { (listIsAccurate and eCpfHeldByOwner) implies all a: Attempt | accepted[a] implies companyWillOf[a.m] }
check RepresentativeSound for 5

-- Expected COUNTEREXAMPLE: a stale list (someone who left the company is still listed).
assert RepresentativeStaleList { eCpfHeldByOwner implies all a: Attempt | accepted[a] implies companyWillOf[a.m] }
check RepresentativeStaleList for 5

-- Expected COUNTEREXAMPLE: an e-CPF operated by someone else (lent token). With no e-CNPJ there is no second
-- signature: this is now the only certificate between the company and the mandate.
assert RepresentativeLentECpf { listIsAccurate implies all a: Attempt | accepted[a] implies companyWillOf[a.m] }
check RepresentativeLentECpf for 5

/* A weaker verifier that does not compare the signed text with the challenge. */
pred acceptedUnbound[a: Attempt] { some a.hasList and a.m.signer in ECpf and a.m.signer.owner in a.m.firm.listed }

-- Expected COUNTEREXAMPLE: without the same-text rule, a representative's signature of another text is reused.
assert RepresentativeNeedsSameText { (listIsAccurate and eCpfHeldByOwner) implies all a: Attempt | acceptedUnbound[a] implies companyWillOf[a.m] }
check RepresentativeNeedsSameText for 5

-- Holds by construction (a consistency check of the rule, not a theorem): with no list nothing is accepted. The
-- e-CPF alone never binds a company.
assert NoListNoAcceptance { all a: Attempt | no a.hasList implies not accepted[a] }
check NoListNoAcceptance for 5

-- Holds by construction: a mandate signed with the company's seal is never accepted.
assert SealNeverAccepted { all a: Attempt | a.m.signer in Seal implies not accepted[a] }
check SealNeverAccepted for 5

/* A verifier that took the seal for a signature, as it takes the e-CNPJ today: the seal is of this company and
   signed this text. */
pred acceptedSealAsSignature[a: Attempt] { a.m.signer in Seal and a.m.signer.of = a.m.firm and a.m.signedText = a.m.challenge }

-- Expected COUNTEREXAMPLE: whoever holds the seal signs without representing the company. It is the flaw
-- IssuanceImpliesCompanyWill found for the e-CNPJ in threats.als, and why the seal may not express the company's will.
assert SealAsSignatureIsCompanyWill { all a: Attempt | acceptedSealAsSignature[a] implies companyWillOf[a.m] }
check SealAsSignatureIsCompanyWill for 5

-- Sanity: the rule accepts something, and that something is the company's will.
run RepresentativeAccepts { listIsAccurate and eCpfHeldByOwner and some a: Attempt | accepted[a] and companyWillOf[a.m] } for 5
