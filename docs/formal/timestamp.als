module timestamp

/* ------------------------------------------------------------------------------------------------------------
 * Time-stamp on the principal's signature (SPEC section 23, D-45).
 *
 * A credential records when the authorization was signed (authorized_by.signed_at). In a self-issued credential
 * that time is written by the signer. A verifier whose policy keeps an authorization signed before the certificate
 * was revoked (revocationEffect, effect "keep") compares the revocation with that time. Whoever holds a stolen key
 * can sign after the revocation and write an earlier time.
 *
 * A time-stamp token (RFC 3161) says the signature already existed at the token's time, and the signer does not
 * choose that time. The model asks what the verifier may conclude from each of the two times.
 *
 * Times are integers 0..10. An absent time is the empty set, and Alloy compares an empty set of integers as 0, so
 * every comparison below is guarded by `some`. A separate module: it shares nothing with the others.
 *
 *   java -jar org.alloytools.alloy.dist.jar exec -f -o out-timestamp docs/formal/timestamp.als
 * ---------------------------------------------------------------------------------------------------------- */

one sig Yes {}

/* The certificate that signs: when its key was stolen (if ever) and when the CRL says it was revoked (if ever). */
one sig Cert { stolen: lone Int, revoked: lone Int }

/* One signature of a mandate. */
one sig S {
  made: one Int,        -- when it was really made (nobody but the signer sees this)
  declared: one Int,    -- the time the credential records (written by whoever assembled it)
  stamp: lone Int,      -- the time of the time-stamp token, when there is one
  byThief: lone Yes     -- made by whoever stole the key, not by the holder
}

fact Times {
  all t: S.made + S.declared + S.stamp + Cert.stolen + Cert.revoked | t >= 0 and t <= 10
  some Cert.revoked implies (some Cert.stolen and Cert.revoked >= Cert.stolen)   -- here a revocation follows a theft
  some S.byThief implies (some Cert.stolen and S.made >= Cert.stolen)           -- the thief signs only once it has the key
  no S.byThief implies S.declared >= S.made                                     -- the holder does not backdate
}

/* The authority does what RFC 3161 says: it stamps a signature that exists, with its own clock. */
pred authorityHonest { some S.stamp implies S.stamp >= S.made }

/* The verifier's rule under "keep", as implemented (revocationEffect): kept only when the revocation comes
   strictly after the time compared; with no time to compare, not kept. */
pred keptOn[t: lone Int] { some t and (no Cert.revoked or Cert.revoked > t) }
pred keptOnDeclared { keptOn[S.declared] }
pred keptOnAttested { keptOn[S.stamp] }

/* What the verifier wants to know: the signature was made before the certificate was revoked. */
pred madeBeforeRevocation { no Cert.revoked or S.made < Cert.revoked }

-- Expected COUNTEREXAMPLE: on the declared time, a signature made after the revocation is kept (backdating).
assert DeclaredTimeSound { keptOnDeclared implies madeBeforeRevocation }
check DeclaredTimeSound for 3 but 5 Int

-- Expected to hold: on the attested time, with an honest authority, what is kept was made before the revocation.
assert AttestedTimeSound { (authorityHonest and keptOnAttested) implies madeBeforeRevocation }
check AttestedTimeSound for 3 but 5 Int

-- Expected COUNTEREXAMPLE: the guarantee is the authority's. One that stamps a time before the signature existed
-- brings backdating back, which is why the verifier chooses which authorities it trusts.
assert AttestedNeedsHonestAuthority { keptOnAttested implies madeBeforeRevocation }
check AttestedNeedsHonestAuthority for 3 but 5 Int

-- Expected COUNTEREXAMPLE: the time-stamp does not close the window between the theft and the revocation. The thief
-- signs and stamps inside it, and the signature is kept. That window is what the CRL measurement is about.
assert AttestedExcludesThief { (authorityHonest and keptOnAttested) implies no S.byThief }
check AttestedExcludesThief for 3 but 5 Int

-- Holds by construction (a consistency check of the rule, not a theorem): with no token there is nothing to
-- compare, and nothing is kept on the attested time.
assert NoStampNotKept { no S.stamp implies not keptOnAttested }
check NoStampNotKept for 3 but 5 Int

-- Sanity: the holder signs, stamps, the key is stolen and the certificate revoked later, and the signature is kept.
run HolderKept { no S.byThief and authorityHonest and some Cert.revoked and keptOnAttested } for 3 but 5 Int

/* ------------------------------------------------------------------------------------------------------------
 * Vector commands. generate-timestamp.py turns the instances into docs/vectors/timestamp-v1.json, and the library
 * replays them with revocationEffect (packages/core/src/timestamp.test.ts).
 *
 *   java -jar org.alloytools.alloy.dist.jar exec -f -r 20 -t xml -o out-timestamp timestamp.als
 *   python3 -I docs/formal/generate-timestamp.py
 * ---------------------------------------------------------------------------------------------------------- */

-- Never revoked: nothing to enforce, whatever the times.
run StampNeverRevoked { no Cert.revoked and some S.stamp and authorityHonest } for 3 but 5 Int
-- Stamped before the revocation: kept.
run StampBeforeRevocation { some Cert.revoked and some S.stamp and authorityHonest and S.stamp < Cert.revoked } for 3 but 5 Int
-- Stamped at the very time of the revocation: not kept (the comparison is strict).
run StampAtRevocation { some Cert.revoked and some S.stamp and authorityHonest and S.stamp = Cert.revoked } for 3 but 5 Int
-- Backdated: made and stamped after the revocation, declared before it. Kept on the declared time, not on the attested.
run BackdatedAfterRevocation { some S.byThief and some Cert.revoked and authorityHonest and S.made > Cert.revoked and some S.stamp and S.declared < Cert.revoked } for 3 but 5 Int
-- No token, declared before the revocation: kept on the declared time, not on the attested.
run NoStampDeclaredBefore { some Cert.revoked and no S.stamp and S.declared < Cert.revoked } for 3 but 5 Int
-- The thief inside the window: kept on both. The library cannot see it, and the vector records that it accepts.
run ThiefInsideWindow { some S.byThief and authorityHonest and keptOnAttested and some Cert.revoked } for 3 but 5 Int
