// Go crypto/x509: parse and verify every CRL in data/pairs.json. Prints JSON lines.
//
// Usage: (cd go && go run .), reads ../data/pairs.json
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type pair struct {
	ID      string   `json:"id"`
	Crl     string   `json:"crl"`
	Issuers []string `json:"issuers"`
}

type result struct {
	Lib     string   `json:"lib"`
	Version string   `json:"version"`
	ID      string   `json:"id"`
	Outcome string   `json:"outcome"`
	Detail  string   `json:"detail"`
	Ms      *float64 `json:"ms"`
}

const data = "../data"

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

func median(fn func() error) (float64, error) {
	var ms []float64
	var err error
	for i := 0; i < 3; i++ {
		t0 := time.Now()
		err = fn()
		ms = append(ms, float64(time.Since(t0).Microseconds())/1000)
	}
	sort.Float64s(ms)
	return ms[1], err
}

func run(p pair) result {
	r := result{Lib: "Go crypto/x509", Version: runtime.Version(), ID: p.ID}
	crl, err := under("crl", p.Crl)
	if err != nil {
		r.Outcome, r.Detail = "parse_error", err.Error()
		return r
	}
	der, err := os.ReadFile(crl)
	if err != nil {
		r.Outcome, r.Detail = "parse_error", err.Error()
		return r
	}
	if _, err := x509.ParseRevocationList(der); err != nil {
		r.Outcome, r.Detail = "parse_error", err.Error()
		return r
	}
	if len(p.Issuers) == 0 {
		r.Outcome = "parsed_no_issuer"
		return r
	}
	last := ""
	for _, name := range p.Issuers {
		path, err := under("cert", name)
		if err != nil {
			last = err.Error()
			continue
		}
		raw, _ := os.ReadFile(path)
		block, _ := pem.Decode(raw)
		if block == nil {
			last = "issuer certificate: not PEM"
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			last = "issuer certificate: " + err.Error()
			continue
		}
		ms, err := median(func() error {
			rl, err := x509.ParseRevocationList(der)
			if err != nil {
				return err
			}
			return rl.CheckSignatureFrom(cert)
		})
		if err == nil {
			r.Outcome, r.Ms = "ok", &ms
			return r
		}
		last = err.Error()
	}
	r.Outcome, r.Detail = "verify_failed", last
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
	enc := json.NewEncoder(os.Stdout)
	for _, p := range in.Pairs {
		if err := enc.Encode(run(p)); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}
