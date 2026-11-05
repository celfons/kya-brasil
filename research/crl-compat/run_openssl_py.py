"""OpenSSL CLI and Python cryptography: parse and verify every CRL in data/pairs.json. Prints JSON lines.

Usage: python3 -I run_openssl_py.py openssl|python
"""
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")


def under(sub, name):
    """Path of `name` inside data/<sub>; refuses anything that would leave it (pairs.json is data, not trusted)."""
    base = os.path.realpath(os.path.join(DATA, sub))
    path = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([path, base]) != base:
        raise ValueError(f"refusing path {name!r}")
    return path


def timed(fn, n=3):
    ms, out = [], None
    for _ in range(n):
        t0 = time.perf_counter()
        out = fn()
        ms.append((time.perf_counter() - t0) * 1000)
    return out, statistics.median(ms)


def openssl_verify(crl, cert):
    r = subprocess.run(["openssl", "crl", "-inform", "DER", "-in", crl, "-CAfile", cert, "-noout"], capture_output=True)
    return (r.stdout + r.stderr).decode()


def openssl(p):
    crl = under("crl", p["crl"])
    r = subprocess.run(["openssl", "crl", "-inform", "DER", "-in", crl, "-noout"], capture_output=True)
    if r.returncode != 0:
        return "parse_error", r.stderr.decode()[:200], None
    if not p["issuers"]:
        return "parsed_no_issuer", "", None
    last = ""
    for name in p["issuers"]:
        out, ms = timed(lambda c=under("cert", name): openssl_verify(crl, c))
        if "verify OK" in out:
            return "ok", "", ms
        last = out.strip()[:200]
    return "verify_failed", last, None


def python(p):
    from cryptography import x509
    with open(under("crl", p["crl"]), "rb") as f:
        der = f.read()
    try:
        x509.load_der_x509_crl(der)
    except Exception as e:  # noqa: BLE001
        return "parse_error", f"{type(e).__name__}: {e}"[:200], None
    if not p["issuers"]:
        return "parsed_no_issuer", "", None
    last = ""
    for name in p["issuers"]:
        try:
            with open(under("cert", name), "rb") as f:
                key = x509.load_pem_x509_certificate(f.read()).public_key()
            ok, ms = timed(lambda k=key: x509.load_der_x509_crl(der).is_signature_valid(k))
            if ok:
                return "ok", "", ms
            last = "is_signature_valid returned False"
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"[:200]
    return "verify_failed", last, None


def main():
    lib = sys.argv[1]
    if lib == "openssl":
        name, fn = "OpenSSL CLI", openssl
        version = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.split()[1]
    elif lib == "python":
        import cryptography
        name, fn, version = "Python cryptography", python, cryptography.__version__
    else:
        raise SystemExit("usage: run_openssl_py.py openssl|python")
    with open(os.path.join(DATA, "pairs.json")) as f:
        pairs = json.load(f)["pairs"]
    for p in pairs:
        outcome, detail, ms = fn(p)
        print(json.dumps({"lib": name, "version": version, "id": p["id"], "outcome": outcome, "detail": detail, "ms": ms}), flush=True)


if __name__ == "__main__":
    main()
