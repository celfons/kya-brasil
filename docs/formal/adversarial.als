/*
 * KYA Brasil: adversarial vectors from the threat model (H4).
 *
 * Each `run` asks Alloy for a concrete instance of threats.als in which the verifier's rule, as implemented, must
 * answer in a known way: accept, or refuse with a specific error. generate-adversarial.py turns the instances into
 * docs/vectors/adversarial-v1.json, and the libraries replay them:
 *   - replay section: packages/agent-tools/src/adversarial.test.ts signs one request and presents it at the
 *     instance's times (1 time unit = 100 s: SKEW 3 = 300 s, MAXLIFE 6 = 600 s, the defaults of createKyaAuth);
 *   - freshness section: packages/core/src/adversarial.test.ts builds the CRL evidence of the instance and asks
 *     checkFreshness (1 time unit = 1 h: MAXAGE 3 = 10 800 s).
 * A "run" that finds no instance is a bug in the model or in the scope; every command below must be SAT.
 *
 * Run: java -jar org.alloytools.alloy.dist.jar exec -q -f -r 20 -t xml -o out-adversarial docs/formal/adversarial.als
 */
open threats

/* ---- (iv) Replay: one signed request, two presentations. Ordered so the first acceptance is the earlier one. ---- */

one sig R extends Req {}
one sig A1, A2 extends Accept {}
fact Ordered { A1.req = R and A2.req = R and A1.at < A2.at }

-- The same request inside its window twice: the first passes, the second is refused by the cache (KYA_REQUEST_REPLAYED).
run ReplayInsideWindow { productRule } for 4 but 5 Int, exactly 1 Req, exactly 2 Accept

-- The second presentation after the request expired: refused by the window (KYA_SIGNATURE_EXPIRED), cache or not.
run ReplayAfterExpiry { inWindow[R, A1.at] and A2.at > R.expires } for 4 but 5 Int, exactly 1 Req, exactly 2 Accept

-- Presented before it was created by more than the skew: refused (KYA_SIGNATURE_NOT_YET_VALID), then accepted in window.
run CreatedInFuture { R.created > plus[A1.at, SKEW] and inWindow[R, A2.at] } for 4 but 5 Int, exactly 1 Req, exactly 2 Accept

-- At the edges: presented exactly at expiry (accepted) and exactly skew ahead of creation (accepted).
run WindowEdges { A1.at = minus[R.created, SKEW] and A2.at = R.expires } for 4 but 5 Int, exactly 1 Req, exactly 2 Accept

/* ---- Freshness: one offline verification with a CRL in hand. ---- */

one sig T extends Attempt {}
fact OfflineWithCrl { T.mode = Offline and T.presented = T and some T.crl }

-- Fresh CRL (age <= MAXAGE) that does not list the certificate: accepted.
run FreshNotListed { accepts[T] and no T.cred.revokedAt } for 4 but 5 Int, exactly 1 Attempt, exactly 1 Crl, exactly 1 Cred

-- Stale CRL (age > MAXAGE), certificate not listed: refused for age alone.
run StaleNotListed { not accepts[T] and not listedIn[T] and minus[T.now, T.crl.thisUpdate] > MAXAGE } for 4 but 5 Int, exactly 1 Attempt, exactly 1 Crl, exactly 1 Cred

-- Fresh CRL that lists the certificate (revoked at or before thisUpdate): refused as revoked.
run FreshListed { listedIn[T] and minus[T.now, T.crl.thisUpdate] <= MAXAGE } for 4 but 5 Int, exactly 1 Attempt, exactly 1 Crl, exactly 1 Cred

-- The residual window: revoked after thisUpdate, CRL still fresh: accepted (the policy bounds this, it does not remove it).
run ResidualWindow { accepts[T] and some T.cred.revokedAt and T.cred.revokedAt > T.crl.thisUpdate and T.cred.revokedAt <= T.now } for 4 but 5 Int, exactly 1 Attempt, exactly 1 Crl, exactly 1 Cred

-- At the edge: CRL exactly MAXAGE old, not listed: accepted.
run AgeEdge { accepts[T] and minus[T.now, T.crl.thisUpdate] = MAXAGE and no T.cred.revokedAt } for 4 but 5 Int, exactly 1 Attempt, exactly 1 Crl, exactly 1 Cred

/* ---- (ii-b) Co-signature of a company mandate by a representative's e-CPF (threats.als, sections "concrete"
 *      and "no list"). One company mandate, one firm; the verifier's list and the e-CNPJ's responsible come from
 *      the instance. The library's answer is verifyCompanyWill on a self-issued company credential. ---- */

one sig M extends CompanyMandate {}
fact OneFirm { #Firm = 1 and #ECnpj = 1 }

-- Co-signer in the verifier's list, same text as the challenge: accepted as the company's will.
run CosignListedSameText { acceptedAsCompanyWill[M] and listIsAccurate and eCpfHeldByOwner } for 4 but 5 Int, exactly 1 CompanyMandate, exactly 1 ECpf

-- Co-signer not in the list (and not the responsible): refused, COSIGNER_NOT_REPRESENTATIVE.
run CosignNotListed { some M.cosigner and M.cosignedText = M.challenge and M.cosigner.owner not in M.ecnpj.firm.listed and M.cosigner.owner != responsibleOf[M.ecnpj] } for 4 but 5 Int, exactly 1 CompanyMandate, exactly 1 ECpf

-- Co-signature over another text: refused, COSIGNATURE_TEXT_MISMATCH.
run CosignOtherText { some M.cosigner and M.cosignedText != M.challenge and M.cosigner.owner in M.ecnpj.firm.listed } for 4 but 5 Int, exactly 1 CompanyMandate, exactly 1 ECpf

-- No co-signature at all: refused, NO_COSIGNATURE, whoever operates the e-CNPJ.
run CosignAbsent { no M.cosigner } for 4 but 5 Int, exactly 1 CompanyMandate, 0 ECpf

-- The responsible named in the e-CNPJ co-signs, with no list: accepted (acceptCertificateResponsible).
run CosignByResponsible { acceptedByResponsible[M] and M.cosigner.owner not in M.ecnpj.firm.listed } for 4 but 5 Int, exactly 1 CompanyMandate, exactly 1 ECpf

-- The trust assumptions the library cannot check, kept as vectors the library ACCEPTS: a stale list (the
-- co-signer left the firm but is still listed) and a lent e-CPF (operated by someone else).
run CosignStaleList { acceptedAsCompanyWill[M] and M.cosigner.operator not in M.ecnpj.firm.realReps and eCpfHeldByOwner } for 4 but 5 Int, exactly 1 CompanyMandate, exactly 1 ECpf
run CosignLentECpf { acceptedAsCompanyWill[M] and listIsAccurate and M.cosigner.operator.cpf != M.cosigner.owner } for 4 but 5 Int, exactly 1 CompanyMandate, exactly 1 ECpf
