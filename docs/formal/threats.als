/*
 * KYA Brasil: threats from the pre-project's threat model (section 2.1) that the mandate model (mandate.als)
 * does not cover. Each threat states the product's CURRENT rule, an assertion of the property one would want,
 * and, where there is one, a mitigation. A counterexample to a current-rule check is expected: it documents a
 * limitation of the product as it is, not a bug in the model.
 *
 * Run: java -jar org.alloytools.alloy.dist.jar exec -f -o out-threats docs/formal/threats.als
 *
 * Time is a small integer; the product's seconds are scaled down: SKEW = 3 stands for the 300 s a signature may
 * be created in the future, MAXLIFE = 6 for the 600 s between KYA-Created and KYA-Expires (SPEC section 14).
 */
module kya/threats

/* ------------------------------------------------------------------------------------------------------------
 * (iv) Replay of a signed request (SPEC section 14).
 *
 * The verifier accepts a signed request when the signature verifies and the clock is inside its window:
 * created <= now + SKEW, now <= expires, expires - created <= MAXLIFE. It keeps no record of requests already
 * accepted (no nonce cache). A Req atom is one signed request (same bytes); an Accept is the verifier accepting
 * it at some time.
 * ---------------------------------------------------------------------------------------------------------- */

fun SKEW: Int { 3 }
fun MAXLIFE: Int { 6 }

sig Req { created: one Int, expires: one Int } {
  expires > created
  minus[expires, created] <= MAXLIFE
}

sig Accept { req: one Req, at: one Int }

/* One verifier, one request at a time: no two acceptances at the same instant. */
fact SerialVerifier { all disj a1, a2: Accept | a1.at != a2.at }

pred inWindow[r: Req, t: Int] { r.created <= plus[t, SKEW] and t <= r.expires }

/* The product's rule today: window only. */
pred productRule { all a: Accept | inWindow[a.req, a.at] }

/* Mitigation: the verifier remembers each accepted request until it expires (memory bounded by the window),
   and refuses one it has already accepted. */
pred rememberUntilExpiry {
  productRule
  all a1, a2: Accept | (a1.req = a2.req and a1.at < a2.at and a2.at <= a1.req.expires) implies a1 = a2
}

/* A weaker memory that forgets after `keep` time units, shorter than the window: shows why the retention must
   last until the request expires. */
pred rememberFor[keep: Int] {
  productRule
  all a1, a2: Accept | (a1.req = a2.req and a1.at < a2.at and a2.at <= plus[a1.at, keep]) implies a1 = a2
}

pred noReplay { all disj a1, a2: Accept | a1.req != a2.req }

-- Expected COUNTEREXAMPLE: the same signed request accepted twice inside its window.
assert NoReplayToday { productRule implies noReplay }
check NoReplayToday for 4 but 5 Int

-- Expected to hold: with memory until expiry, a request is accepted at most once.
assert NoReplayWithMemory { rememberUntilExpiry implies noReplay }
check NoReplayWithMemory for 4 but 5 Int

-- Expected COUNTEREXAMPLE: forgetting after 2 units (less than the 6-unit window) lets a replay through.
assert NoReplayShortMemory { rememberFor[2] implies noReplay }
check NoReplayShortMemory for 4 but 5 Int

-- Sanity: the mitigation still accepts requests (not vacuous).
run AcceptsWithMemory { rememberUntilExpiry and #Accept = 2 and #Req = 2 } for 4 but 5 Int

/* ------------------------------------------------------------------------------------------------------------
 * (ii-b) The certificate holder is not necessarily the company's legal representative.
 *
 * An e-CNPJ names the company; whoever holds it (an A1 file, a token) can sign. Issuance and verification check
 * the certificate, its chain and its revocation, never who operated it. Representatives come from the company's
 * articles (the Receita's QSA), which the product does not read.
 * ---------------------------------------------------------------------------------------------------------- */

sig Person {}
sig Company { reps: set Person }
sig Cert { company: one Company, holder: one Person }
/* A credential exists only if its certificate signed the mandate (what the product checks). */
sig Credential { cert: one Cert }

/* Proposal, not current behaviour: the mandate is also signed with the e-CPF of a person the verifier knows to be
   a representative of the company (e.g. from the QSA). */
sig CoSignature { cred: one Credential, signer: one Person }

pred companyWill[c: Credential] { c.cert.holder in c.cert.company.reps or some s: CoSignature | s.cred = c and s.signer in c.cert.company.reps }
pred holderIsRepresentative[c: Credential] { c.cert.holder in c.cert.company.reps }

pred proposalCoSign { all c: Credential | some s: CoSignature | s.cred = c and s.signer in c.cert.company.reps }

-- Expected COUNTEREXAMPLE: a credential issued with the company's certificate by someone who does not represent it.
assert IssuanceImpliesCompanyWill { all c: Credential | holderIsRepresentative[c] }
check IssuanceImpliesCompanyWill for 4

-- Holds by construction under the proposal: its strength is entirely in the assumption that the verifier knows
-- the representatives and verifies the co-signer's e-CPF.
assert CoSignedImpliesCompanyWill { proposalCoSign implies all c: Credential | companyWill[c] }
check CoSignedImpliesCompanyWill for 4

-- Sanity: the proposal admits the accountant case (holder is not a representative, a representative co-signs).
run AccountantWithCoSignature { proposalCoSign and some c: Credential | not holderIsRepresentative[c] } for 4
