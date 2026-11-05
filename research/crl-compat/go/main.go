// Go crypto/x509: parse and verify every CRL in data/pairs.json. Prints JSON lines.
//
// Usage: go run . ../data/pairs.json
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"sort"
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
	der, err := os.ReadFile(p.Crl)
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
	for _, path := range p.Issuers {
		raw, _ := os.ReadFile(path)
		block, _ := pem.Decode(raw)
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
	raw, err := os.ReadFile(os.Args[1])
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
