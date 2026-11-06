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

/* ------------------------------------------------------------------------------------------------------------
 * (iv, implemented) The replay cache of createKyaAuth({ replayCache }) (agent-tools 0.13.0).
 *
 * After a request fully verifies, the verifier calls seen(sha256(request text), expires, now): an entry for the
 * same text that is still live (now <= its expiry) means "already seen" and the request is refused; otherwise an
 * entry is recorded with expiry = the request's own `expires`. memoryReplayCache evicts an entry once the clock
 * passes its expiry. The clock that evicts is the verifier's (`now` passed to seen); EvictDrift models a store
 * whose clock runs ahead of the verifier's, to show why the clock must be the same. A full cache refuses, which
 * only removes acceptances and is left out.
 * ---------------------------------------------------------------------------------------------------------- */

/* One cache entry per accepted request: recorded at the acceptance, keyed by the request (its text), kept until
   `keepUntil`. */
sig Entry { of: one Accept, keepUntil: one Int }

fact EntriesComeFromAccepts { all a: Accept | one e: Entry | e.of = a }

/* Keep times in 0..10 so that the arithmetic below cannot wrap around in 5-bit Int. */
pred smallClock { all a: Accept | a.at >= 0 and a.at <= 10 and a.req.created >= 0 and a.req.expires <= 10 }

/* An entry is live at time t, for a store whose clock reads t + drift. */
pred live[e: Entry, t: Int, drift: Int] { e.of.at < t and plus[t, drift] <= e.keepUntil }

/* The implemented rule: window (productRule) and no live entry for the same request; entries kept until the
   request's own expiry; eviction by `drift` ahead of the verifier's clock (0 = the verifier's clock). */
pred implementedCache[drift: Int] {
  smallClock
  productRule
  all e: Entry | e.keepUntil = e.of.req.expires
  all a: Accept | no e: Entry | e.of.req = a.req and live[e, a.at, drift]
}

-- Expected to hold: the cache as implemented (TTL = the request's expiry, verifier's clock) prevents replay.
assert NoReplayImplemented { implementedCache[0] implies noReplay }
check NoReplayImplemented for 4 but 5 Int

-- Expected COUNTEREXAMPLE: a store that evicts by a clock 2 units ahead of the verifier's forgets a request that
-- the window still accepts. Hence seen() receives the verifier's clock.
assert NoReplayClockDrift { implementedCache[2] implies noReplay }
check NoReplayClockDrift for 4 but 5 Int

-- Sanity: the implemented cache accepts two different requests, and the same request again after it expired is
-- refused by the window, not by the cache.
run ImplementedAccepts { implementedCache[0] and #Accept = 2 and #Req = 2 } for 4 but 5 Int

/* ------------------------------------------------------------------------------------------------------------
 * (ii-b, concrete) Co-signature of a company mandate by a representative's e-CPF.
 *
 * Design: the company mandate carries a second CMS over the SAME challenge text, by an e-CPF; the verifier
 * supplies representatives(cnpj) -> cpf[] (e.g. from the QSA) and accepts the credential as the company's will only
 * when the e-CPF's CPF is in that list. People and CPFs are separate: the list holds CPFs, an e-CPF names a CPF and
 * is held (operated) by some person.
 * ---------------------------------------------------------------------------------------------------------- */

sig Cpf {}
sig Human { cpf: one Cpf }
fact CpfIsUnique { all disj h1, h2: Human | h1.cpf != h2.cpf }

/* Truth: who really represents the company today. Verifier: the CPF list it was given. */
sig Firm { realReps: set Human, listed: set Cpf }

sig Text {}
sig ECnpj { firm: one Firm, operator: one Human }
sig ECpf { owner: one Cpf, operator: one Human }

/* A company mandate: the e-CNPJ's CMS over `challenge`, optionally an e-CPF CMS over `cosignedText`. */
sig CompanyMandate { ecnpj: one ECnpj, challenge: one Text, cosigner: lone ECpf, cosignedText: lone Text } {
  some cosigner iff some cosignedText
}

/* The verifier's rule (co-signature design). */
pred acceptedAsCompanyWill[m: CompanyMandate] {
  some m.cosigner
  m.cosignedText = m.challenge
  m.cosigner.owner in m.ecnpj.firm.listed
}

/* What we want: a real representative, in person, agreed to THIS mandate. */
pred companyWillOf[m: CompanyMandate] { some m.cosigner and m.cosignedText = m.challenge and m.cosigner.operator in m.ecnpj.firm.realReps }

/* Assumptions the design rests on. */
pred listIsAccurate { all f: Firm | f.listed in f.realReps.cpf }
pred eCpfHeldByOwner { all c: ECpf | c.operator.cpf = c.owner }

-- Expected to hold: accurate list and e-CPFs operated by their owners => accepted implies the company's will.
assert CoSignatureSound { (listIsAccurate and eCpfHeldByOwner) implies all m: CompanyMandate | acceptedAsCompanyWill[m] implies companyWillOf[m] }
check CoSignatureSound for 5

-- Expected COUNTEREXAMPLE: a stale list (someone who left the QSA is still listed).
assert CoSignatureStaleList { eCpfHeldByOwner implies all m: CompanyMandate | acceptedAsCompanyWill[m] implies companyWillOf[m] }
check CoSignatureStaleList for 5

-- Expected COUNTEREXAMPLE: an e-CPF operated by someone else (lent token, stolen A1): the residual risk moves from
-- the e-CNPJ to the representative's own certificate.
assert CoSignatureLentECpf { listIsAccurate implies all m: CompanyMandate | acceptedAsCompanyWill[m] implies companyWillOf[m] }
check CoSignatureLentECpf for 5

/* A weaker verifier that does not compare the co-signed text with the challenge. */
pred acceptedUnbound[m: CompanyMandate] { some m.cosigner and m.cosigner.owner in m.ecnpj.firm.listed }

-- Expected COUNTEREXAMPLE: without the same-text rule, a representative's co-signature of another mandate is
-- reused for a larger one.
assert CoSignatureNeedsSameText { (listIsAccurate and eCpfHeldByOwner) implies all m: CompanyMandate | acceptedUnbound[m] implies companyWillOf[m] }
check CoSignatureNeedsSameText for 5

-- Expected to hold: with no co-signature the credential is never accepted as the company's will (the e-CNPJ
-- alone, whoever operates it, is not enough).
assert NoCoSignatureNoCompanyWill { all m: CompanyMandate | no m.cosigner implies not acceptedAsCompanyWill[m] }
check NoCoSignatureNoCompanyWill for 5

-- Sanity: the accountant case is accepted (the e-CNPJ operated by a non-representative, a listed representative
-- co-signs the same text).
run AccountantCoSigned { listIsAccurate and eCpfHeldByOwner and some m: CompanyMandate | acceptedAsCompanyWill[m] and m.ecnpj.operator not in m.ecnpj.firm.realReps } for 5

/* ------------------------------------------------------------------------------------------------------------
 * (ii-b, no list) Co-signature by the person responsible named in the e-CNPJ itself.
 *
 * Every e-CNPJ carries, in the otherName 2.16.76.1.3.4 (DOC-ICP-04), the CPF of the person responsible for the
 * certificate before the Receita; the registration authority checks, at issuance, that this person represents the
 * company. verifyCompanyWill({ acceptCertificateResponsible: true }) counts as a representative an e-CPF whose CPF
 * is that one, with no list from the verifier. The trust moves from the verifier's list to the ICP-Brasil issuance
 * and to the e-CNPJ being revoked when that person stops representing the company.
 * ---------------------------------------------------------------------------------------------------------- */

sig Responsible { ecnpjOf: one ECnpj, named: one Cpf }
fact OneResponsiblePerECnpj { all e: ECnpj | one r: Responsible | r.ecnpjOf = e }
fun responsibleOf[e: ECnpj]: one Cpf { (ecnpjOf.e).named }

/* The verifier's rule with no list: the co-signer's CPF is the one the e-CNPJ names. */
pred acceptedByResponsible[m: CompanyMandate] {
  some m.cosigner
  m.cosignedText = m.challenge
  m.cosigner.owner = responsibleOf[m.ecnpj]
}

/* Assumption: the person the e-CNPJ names still represents the company (true at issuance; an e-CNPJ whose
   responsible left must be revoked). */
pred responsibleIsCurrent { all e: ECnpj | responsibleOf[e] in e.firm.realReps.cpf }

-- Expected to hold: with the responsible current and e-CPFs operated by their owners, acceptance implies the
-- company's will, with no list supplied by the verifier.
assert ResponsibleCoSignatureSound { (responsibleIsCurrent and eCpfHeldByOwner) implies all m: CompanyMandate | acceptedByResponsible[m] implies companyWillOf[m] }
check ResponsibleCoSignatureSound for 5

-- Expected COUNTEREXAMPLE: the responsible left the company and the e-CNPJ was not revoked.
assert ResponsibleCoSignatureLeft { eCpfHeldByOwner implies all m: CompanyMandate | acceptedByResponsible[m] implies companyWillOf[m] }
check ResponsibleCoSignatureLeft for 5

-- Expected to hold: the e-CNPJ alone, whoever operates it, is still not the company's will.
assert NoCoSignatureNoResponsibleWill { all m: CompanyMandate | no m.cosigner implies not acceptedByResponsible[m] }
check NoCoSignatureNoResponsibleWill for 5

-- Sanity: the accountant case is accepted with no list (the accountant operates the e-CNPJ, the responsible
-- it names co-signs the same text).
run AccountantResponsibleCoSigned { responsibleIsCurrent and eCpfHeldByOwner and some m: CompanyMandate | acceptedByResponsible[m] and m.ecnpj.operator not in m.ecnpj.firm.realReps } for 5

/* ------------------------------------------------------------------------------------------------------------
 * Issuer unavailability.
 *
 * Online mode: the credential's status comes from the hosted issuer; when it is down the verifier answers
 * 502 KYA_ISSUER_UNAVAILABLE (fail closed). Offline mode: the request carries the credential (self-issued or with
 * the principal's proof) and the verifier checks the certificate against a CRL it holds; with issuerFallback, a
 * request WITHOUT the credential still goes to the issuer. The action is allowed (check()/allowed()) only when the
 * CRL is at most MAXAGE old at the verifier's clock (freshness policy, SPEC section 18). A CRL lists every
 * revocation made up to its thisUpdate. Time is small integers; MAXAGE = 3.
 * ---------------------------------------------------------------------------------------------------------- */

fun MAXAGE: Int { 3 }

abstract sig Mode {}
one sig OnlineOnly, Offline, OfflineWithFallback extends Mode {}

sig Crl { thisUpdate: one Int }
sig Cred { revokedAt: lone Int }

/* One verification at time `now`: the verifier's mode, whether the issuer answers, whether the request carries
   the credential, and the CRL the verifier holds. */
sig Attempt { mode: one Mode, now: one Int, issuerUp: lone Attempt, presented: lone Attempt, cred: one Cred, crl: lone Crl } {
  issuerUp in this
  presented in this
  some crl implies crl.thisUpdate <= now
}

/* Times in 0..10 (no wrap-around in 5-bit Int). */
fact SmallTimes { all a: Attempt | a.now >= 0 and a.now <= 10 and (some a.crl implies a.crl.thisUpdate >= 0) and (all c: Cred | some c.revokedAt implies (c.revokedAt >= 0 and c.revokedAt <= 10)) }

pred revokedBy[c: Cred, t: Int] { some c.revokedAt and c.revokedAt <= t }
/* The CRL lists the credential's certificate iff it was revoked by thisUpdate. */
pred listedIn[a: Attempt] { some a.crl and revokedBy[a.cred, a.crl.thisUpdate] }
/* The issuer answers with the current status. */
pred issuerSaysActive[a: Attempt] { some a.issuerUp and not revokedBy[a.cred, a.now] }

pred viaIssuer[a: Attempt] { a.mode = OnlineOnly or (a.mode = OfflineWithFallback and no a.presented) }
pred viaOffline[a: Attempt] { not viaIssuer[a] }

/* The rule as implemented, with the freshness policy on; `fresh` = whether that policy is applied. */
pred acceptsFresh[a: Attempt, fresh: Int] {
  viaIssuer[a] implies issuerSaysActive[a]
  viaOffline[a] implies (some a.presented and some a.crl and not listedIn[a] and (fresh = 1 implies minus[a.now, a.crl.thisUpdate] <= MAXAGE))
}
pred accepts[a: Attempt] { acceptsFresh[a, 1] }

-- Expected to hold: online-only fails closed when the issuer is down; so does the fallback path.
assert IssuerDownFailsClosed { all a: Attempt | (no a.issuerUp and viaIssuer[a]) implies not accepts[a] }
check IssuerDownFailsClosed for 4 but 5 Int

-- Expected to hold: offline (and the fallback when the credential comes along) never depends on the issuer:
-- whether it accepts is the same with the issuer up or down.
assert OfflineIndependentOfIssuer { all a, b: Attempt | (a.mode = b.mode and a.now = b.now and a.presented = a and b.presented = b and a.cred = b.cred and a.crl = b.crl and viaOffline[a]) implies (accepts[a] iff accepts[b]) }
check OfflineIndependentOfIssuer for 4 but 5 Int

-- Expected to hold: the offline path never accepts a certificate revoked MAXAGE or more ago (the CRL, fresher
-- than the policy, lists it).
assert NoStaleRevokedAccepted { all a: Attempt | (accepts[a] and viaOffline[a]) implies not revokedBy[a.cred, minus[a.now, MAXAGE]] }
check NoStaleRevokedAccepted for 4 but 5 Int

-- Expected COUNTEREXAMPLE: without the freshness policy, an old CRL lets a long-revoked certificate through.
assert NoStaleRevokedWithoutPolicy { all a: Attempt | (acceptsFresh[a, 0] and viaOffline[a]) implies not (some a.cred.revokedAt and a.cred.revokedAt <= minus[a.now, MAXAGE]) }
check NoStaleRevokedWithoutPolicy for 4 but 5 Int

-- Expected COUNTEREXAMPLE: the residual window. A certificate revoked less than MAXAGE ago, after the CRL was
-- issued, is accepted; the policy bounds this exposure, it does not remove it.
assert NoRevokedAcceptedOffline { all a: Attempt | (accepts[a] and viaOffline[a]) implies not revokedBy[a.cred, a.now] }
check NoRevokedAcceptedOffline for 4 but 5 Int

-- Sanity: with the hosted issuer down, an offline verifier accepts a self-presented credential with a fresh CRL,
-- while an online-only verifier refuses the same credential at the same time.
run IssuerDownOfflineStillAccepts { some disj a, b: Attempt | no a.issuerUp and no b.issuerUp and a.mode = Offline and b.mode = OnlineOnly and a.cred = b.cred and a.now = b.now and accepts[a] and not accepts[b] } for 4 but 5 Int
