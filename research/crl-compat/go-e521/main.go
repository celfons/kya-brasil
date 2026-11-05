// Ed521 (id-Ed521, 1.3.6.1.4.1.44588.2.1, DOC-ICP-01.01): verifies the CRLs in ../data/pairs.json signed with that
// OID, and the issuer certificate's own signature, two ways. Prints JSON lines in the format of the other runners;
// CRLs with other algorithms are skipped. Usage: (cd go-e521 && go run .)
//
//   - "Go e521": the Verify method of github.com/pedroalbanese/e521, the only implementation found. It reduces the
//     first 66 bytes of the 132-byte SHAKE256 output modulo the group order.
//   - "Ed521, full hash": the same curve arithmetic from that package, with k = SHAKE256(dom5 || R || A || M, 132)
//     read whole as a little-endian integer modulo the order, as RFC 8032 does for Ed448 (dom5 = "SigEd521" ||
//     phflag 0 || context length 0). This is the form AC Raiz v7's signatures satisfy.
package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/pedroalbanese/e521"
	"golang.org/x/crypto/sha3"
)

const (
	data     = "../data"
	oidEd521 = "1.3.6.1.4.1.44588.2.1"
)

type pair struct {
	ID        string   `json:"id"`
	Crl       string   `json:"crl"`
	Algorithm string   `json:"algorithm"`
	Issuers   []string `json:"issuers"`
}

type result struct {
	Lib     string   `json:"lib"`
	Version string   `json:"version"`
	ID      string   `json:"id"`
	Outcome string   `json:"outcome"`
	Detail  string   `json:"detail"`
	Ms      *float64 `json:"ms"`
}

// under is the path of name inside data/<sub>; it refuses anything that would leave it (pairs.json is data).
func under(sub, name string) (string, error) {
	base, err := filepath.Abs(filepath.Join(data, sub))
	if err != nil {
		return "", err
	}
	path := filepath.Join(base, name)
	if rel, err := filepath.Rel(base, path); err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("refusing path %q", name)
	}
	return path, nil
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/pedroalbanese/e521" {
				return strings.TrimPrefix(d.Version, "v")
			}
		}
	}
	return "unknown"
}

func readCert(name string) (*x509.Certificate, error) {
	path, err := under("cert", name)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// publicKey reads an id-Ed521 SubjectPublicKeyInfo. e521.ParsePublicKey requires the AlgorithmIdentifier's
// parameters field, which AC Raiz v7's certificate omits, so the SPKI is read here and the point decompressed by the
// package.
func publicKey(spki []byte) (*e521.PublicKey, error) {
	var info struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue `asn1:"optional"`
		}
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(spki, &info); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("SubjectPublicKeyInfo: %v", err)
	}
	if info.Algorithm.Algorithm.String() != oidEd521 {
		return nil, fmt.Errorf("public key algorithm %s is not id-Ed521", info.Algorithm.Algorithm)
	}
	x, y := e521.E521().DecompressPoint(info.PublicKey.Bytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("public key is not a point of E-521")
	}
	return e521.NewPublicKey(x, y), nil
}

// le reads b as a little-endian integer; leb writes n as l little-endian bytes.
func le(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(r)
}

func leb(n *big.Int, l int) []byte {
	b := n.Bytes()
	out := make([]byte, l)
	for i := 0; i < len(b) && i < l; i++ {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// verifyFullHash checks sig = R || s over msg for the compressed key a, with the whole 132-byte hash (see above).
func verifyFullHash(a, msg, sig []byte) bool {
	c := e521.E521()
	n := (c.BitSize + 7) / 8
	if len(sig) != 2*n || len(a) != n {
		return false
	}
	r, s := sig[:n], le(sig[n:])
	if s.Cmp(c.N) >= 0 {
		return false
	}
	ax, ay := c.DecompressPoint(a)
	rx, ry := c.DecompressPoint(r)
	if ax == nil || rx == nil {
		return false
	}
	h := sha3.NewShake256()
	for _, part := range [][]byte{[]byte("SigEd521"), {0, 0}, r, a, msg} {
		h.Write(part)
	}
	digest := make([]byte, 2*n)
	h.Read(digest)
	k := new(big.Int).Mod(le(digest), c.N)
	sgx, sgy := c.ScalarBaseMult(leb(s, n))
	hax, hay := c.ScalarMult(ax, ay, leb(k, n))
	x, y := c.Add(rx, ry, hax, hay)
	return sgx.Cmp(x) == 0 && sgy.Cmp(y) == 0
}

type verifier struct {
	lib string
	fn  func(pub *e521.PublicKey, key, msg, sig []byte) bool
}

var verifiers = []verifier{
	{"Go e521", func(pub *e521.PublicKey, _, msg, sig []byte) bool { return pub.Verify(msg, sig) }},
	{"Ed521, full hash", func(_ *e521.PublicKey, key, msg, sig []byte) bool { return verifyFullHash(key, msg, sig) }},
}

// check verifies the CRL against one issuer, whose own (self-)signature must also verify.
func check(v verifier, der []byte, cert *x509.Certificate) (float64, error) {
	pub, err := publicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return 0, err
	}
	key := e521.E521().CompressPoint(pub.X, pub.Y)
	if !v.fn(pub, key, cert.RawTBSCertificate, cert.Signature) {
		return 0, fmt.Errorf("issuer certificate signature does not verify")
	}
	var ms []float64
	for i := 0; i < 3; i++ {
		t0 := time.Now()
		rl, err := x509.ParseRevocationList(der)
		if err != nil {
			return 0, err
		}
		if !v.fn(pub, key, rl.RawTBSRevocationList, rl.Signature) {
			return 0, fmt.Errorf("CRL signature does not verify")
		}
		ms = append(ms, float64(time.Since(t0).Microseconds())/1000)
	}
	sort.Float64s(ms)
	return ms[1], nil
}

func run(v verifier, p pair, ver string) result {
	r := result{Lib: v.lib, Version: ver, ID: p.ID}
	path, err := under("crl", p.Crl)
	if err == nil {
		var der []byte
		if der, err = os.ReadFile(path); err == nil {
			for _, name := range p.Issuers {
				var cert *x509.Certificate
				if cert, err = readCert(name); err != nil {
					continue
				}
				var ms float64
				if ms, err = check(v, der, cert); err == nil {
					r.Outcome, r.Ms = "ok", &ms
					return r
				}
			}
		}
	}
	r.Outcome = "verify_failed"
	if err != nil {
		r.Detail = err.Error()
	}
	return r
}

func main() {
	raw, err := os.ReadFile(filepath.Join(data, "pairs.json"))
	if err != nil {
		panic(err)
	}
	var in struct{ Pairs []pair }
	if err := json.Unmarshal(raw, &in); err != nil {
		panic(err)
	}
	ver, enc := version(), json.NewEncoder(os.Stdout)
	for _, v := range verifiers {
		for _, p := range in.Pairs {
			if p.Algorithm != oidEd521 {
				continue
			}
			if err := enc.Encode(run(v, p, ver)); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
	}
}
