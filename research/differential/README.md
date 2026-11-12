# research/differential

`@kya-brasil/core` against OpenSSL, on the same bytes. The library and its vectors come from one author, so their
agreement does not show that either is right. OpenSSL is an implementation the author did not write.

Three comparisons, in `compare.mjs`:

1. **The entries of the CRLs of a cut.** Every CRL that `research/freshness-sim/fetch_measured.py` named in
   `data/measured.json` is read by the core's DER reader (`crl-der.ts`) and by `openssl crl -text`. The two dates,
   the number of entries and, for every entry, the serial number, the revocation date and the reason must be equal.
2. **Mutated CRLs.** 200 mutants of each list (one bit, one byte of the header, a truncation, or four bytes in a
   row), from a fixed seed. The core's reader must answer with a parsed list or a `DerError`, never fail in another
   way. Where both readers accept a mutant, they must read the same dates. For the lists whose AC certificate is in
   `anchors/icp-brasil.pem`, `verifyCrl` and `openssl crl -CAfile` verify the signature of each mutant: the core
   must not verify what OpenSSL refuses.
3. **The CMS signature of the self-issued vector** (`docs/vectors/self-issued-v1.json`), verified by
   `verifyIcpSignature` and by `openssl cms -verify`, over the signed text, over another text, and over 2 000
   mutants of one bit.

```bash
pnpm --filter @kya-brasil/research-differential all
```

Needs network access to the collector (`fetch.py`, once per cut), `openssl` and Python 3. `data/` is not committed.
`results/results.json` and `results/RESULTS.md` are, with the cut, the version of the core, the commit and the
version of OpenSSL.

## What the run of 12 November 2026 found

Cut of 7 November 2026, core 0.22.0, OpenSSL 3.0.13.

- **Entries.** The 100 lists and their 340 588 entries are read the same by both, the 53 398 reasons included.
  Two Serpro lists carry 12 negative serial numbers, which RFC 5280 forbids. OpenSSL prints them as a minus sign
  and the magnitude. The core indexes a serial by the content bytes of the INTEGER, the form in which a
  certificate's serial reaches it, and finds all 12.
- **Mutated CRLs, reading.** Of 20 000 mutants the core's reader parsed 11 198 and refused 8 802 with `DerError`.
  It never failed in another way, and the slowest answer took under 0.2 s. The two readers disagree on what they
  accept without the signature: the core reads the entries only when one is looked up, and OpenSSL decodes every
  field; OpenSSL accepts times and algorithm fields the core refuses. No mutant accepted by both gave different
  dates.
- **Mutated CRLs, signature.** For the 76 lists whose AC certificate is among the anchors, 15 200 mutants: both
  verify 12, both refuse 15 183, OpenSSL alone verifies 5, and the core alone verifies none.
- **CMS.** Both accept the vector and both refuse the same signature over another text. Of 2 000 mutants of one
  bit, both refuse 1 290 and both accept 278. OpenSSL alone accepts 396, which the core refuses when it validates
  the chain with the certificates the CMS carries. The core alone accepts 36.

## The 36 mutants only the core accepts

None of them changes the signed text, the signer's key or the signed fields of the certificate. They are
encodings OpenSSL refuses in fields the verification does not use, and the core accepts them because PKI.js and
asn1js, which decode the CMS, are lenient there:

| Where | Mutants |
|---|---:|
| The content type of the outer ContentInfo is no longer signedData | 11 |
| The digest algorithm in the `digestAlgorithms` set of SignedData | 10 |
| A length byte made shorter (SignedData, the certificate, the set of signers, the issuer name of the signer identifier, its digest algorithm) | 12 |
| The unsigned part of the signer's certificate (parameters of the outer algorithm, unused bits of the signature) | 2 |
| The string type of a name in the signer identifier | 1 |

The consequence is that one signature has more than one accepted encoding. Nothing in the library uses the bytes
of the CMS as an identifier of the signature, and whoever does should hash the signed text and the certificate,
which the library returns. Refusing these encodings in the library is a decision still open: a strict DER check
would also refuse CMS files that real signers write in BER.

## What this does not show

OpenSSL knows nothing of the mandate. The rules of the mandate, of delegation and of issuance have no second
implementation. `research/mutation` measures how many faults injected in those rules the tests and vectors catch.
