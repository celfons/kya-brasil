package main

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// With data/ from fetch.py: the full-hash form accepts AC Raiz v7's CRL and refuses it with one TBS byte flipped.
func TestFullHashOnAcRaizV7(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(data, "pairs.json"))
	if err != nil {
		t.Skip("run fetch.py first")
	}
	var in struct{ Pairs []pair }
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	for _, p := range in.Pairs {
		if p.Algorithm != oidEd521 || len(p.Issuers) == 0 {
			continue
		}
		path, _ := under("crl", p.Crl)
		der, _ := os.ReadFile(path)
		cert, err := readCert(p.Issuers[0])
		if err != nil {
			t.Fatal(err)
		}
		pub, err := publicKey(cert.RawSubjectPublicKeyInfo)
		if err != nil {
			t.Fatal(err)
		}
		key := pub.Curve.CompressPoint(pub.X, pub.Y)
		rl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		if !verifyFullHash(key, rl.RawTBSRevocationList, rl.Signature) {
			t.Fatalf("%s: full-hash Ed521 should verify", p.ID)
		}
		tbs := append([]byte{}, rl.RawTBSRevocationList...)
		tbs[len(tbs)-1] ^= 1
		if verifyFullHash(key, tbs, rl.Signature) {
			t.Fatalf("%s: a tampered TBSCertList must not verify", p.ID)
		}
		return
	}
	t.Skip("no Ed521 CRL in data/pairs.json")
}
