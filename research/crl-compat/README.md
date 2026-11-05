# research/crl-compat

Which X.509 libraries can parse and verify the CRLs the ICP-Brasil actually publishes. It fetches the current CRL of
every source the kya-icp collector follows (`sources.json`, a snapshot of `kya-icp/sources.json`), pairs each with the
certificate of its issuer, and runs:

| Library | How |
|---|---|
| OpenSSL CLI | `openssl crl -inform DER -CAfile <issuer> -noout` |
| Go `crypto/x509` | `ParseRevocationList` + `CheckSignatureFrom` (`go/`) |
| Python `cryptography` | `load_der_x509_crl` + `is_signature_valid` |
| `@peculiar/x509` | `new X509Crl(der).verify({ publicKey: new X509Certificate(issuer) })` |
| PKI.js | `CertificateRevocationList.fromBER(der).verify({ issuerCertificate })` |
| node-forge | no CRL API |
| `@kya-brasil/core` | `verifyCrl({ crlDer, issuerCertificate, pastNextUpdate: "accept" })` |

```bash
pnpm --filter @kya-brasil/research-crl-compat all
```

Needs network access to the ACs' repositories, `openssl`, Go 1.24 and Python 3 with `cryptography`. `fetch.py` writes
`data/` (not committed: the CRLs change every few hours). `run.sh` writes `data/results.jsonl`, then `report.py` writes
`results/results.json` and `results/RESULTS.md`, which are committed with the date of the fetch. Results depend on the
day's CRLs and on the library versions recorded in them.

Issuer certificates come from `anchors/icp-brasil.pem`, the AC Raiz roots v2 to v12 at
`http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/`, and, for retired ACs, the CRL's Authority Information Access
(caIssuers). A CRL whose issuer is not found is parsed but not verified.
