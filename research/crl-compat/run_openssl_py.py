"""OpenSSL CLI and Python cryptography: parse and verify every CRL in data/pairs.json. Prints JSON lines.

Usage: python3 -I run_openssl_py.py data/pairs.json openssl|python
"""
import json, statistics, subprocess, sys, time


def timed(fn, n=3):
    ms, out = [], None
    for _ in range(n):
        t0 = time.perf_counter()
        out = fn()
        ms.append((time.perf_counter() - t0) * 1000)
    return out, statistics.median(ms)


def openssl(p):
    def parse():
        return subprocess.run(["openssl", "crl", "-inform", "DER", "-in", p["crl"], "-noout"], capture_output=True)
    r, _ = timed(parse, 1)
    if r.returncode != 0:
        return "parse_error", r.stderr.decode()[:200], None
    if not p["issuers"]:
        return "parsed_no_issuer", "", None
    last = ""
    for cert in p["issuers"]:
        def verify():
            return subprocess.run(["openssl", "crl", "-inform", "DER", "-in", p["crl"], "-CAfile", cert, "-noout"], capture_output=True)
        r, ms = timed(verify)
        err = (r.stdout + r.stderr).decode()
        if "verify OK" in err:
            return "ok", "", ms
        last = err.strip()[:200]
    return "verify_failed", last, None


def python(p):
    from cryptography import x509
    try:
        der = open(p["crl"], "rb").read()
        crl, _ = timed(lambda: x509.load_der_x509_crl(der), 1)
    except Exception as e:  # noqa: BLE001
        return "parse_error", f"{type(e).__name__}: {e}"[:200], None
    if not p["issuers"]:
        return "parsed_no_issuer", "", None
    last = ""
    for cert in p["issuers"]:
        try:
            key = x509.load_pem_x509_certificate(open(cert, "rb").read()).public_key()
            def verify():
                return x509.load_der_x509_crl(der).is_signature_valid(key)
            ok, ms = timed(verify)
            if ok:
                return "ok", "", ms
            last = "is_signature_valid returned False"
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"[:200]
    return "verify_failed", last, None


def main():
    pairs = json.load(open(sys.argv[1]))["pairs"]
    lib = sys.argv[2]
    if lib == "openssl":
        version = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.split()[1]
        fn = openssl
    else:
        import cryptography
        version = cryptography.__version__
        fn = python
    for p in pairs:
        outcome, detail, ms = fn(p)
        print(json.dumps({"lib": "OpenSSL CLI" if lib == "openssl" else "Python cryptography", "version": version, "id": p["id"], "outcome": outcome, "detail": detail, "ms": ms}), flush=True)


if __name__ == "__main__":
    main()
