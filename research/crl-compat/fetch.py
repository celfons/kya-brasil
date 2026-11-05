"""Downloads the current CRL of every source in sources.json (a snapshot of kya-icp/sources.json) and the ICP-Brasil
root certificates the anchors bundle lacks, then pairs each CRL with the certificates whose subject equals its issuer.

Writes data/crl/<id>.crl, data/cert/*.pem and data/pairs.json. Run with python3 -I from this directory.
"""
import json, os, re, subprocess, sys, urllib.parse, urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
ANCHORS = os.path.join(HERE, "..", "..", "anchors", "icp-brasil.pem")
# The kya-icp collector keeps every CRL version it fetched (R2): used when an AC's server does not answer this run.
COLLECTOR = os.environ.get("KYA_ICP_COLLECTOR", "https://kya-icp-collector.marcelfons.workers.dev")
ROOTS = [f"http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv{v}.crt" for v in range(2, 13)]


def get(url, timeout=90):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read()


def from_collector(source_id):
    """Latest copy of `source_id` in the collector, fetched with the curl CLI (the collector refuses urllib's agent)."""
    curl = lambda path: subprocess.run(["curl", "-sS", "--fail", "--max-time", "120", COLLECTOR + path], capture_output=True, check=True).stdout
    files = json.loads(curl("/api/files/" + urllib.parse.quote(source_id)))["files"]
    if not files:
        raise RuntimeError("collector has no copy")
    key = max(files, key=lambda f: f["uploaded"])["key"]
    return key, curl("/files/" + urllib.parse.quote(key))


def ossl(args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True)


def to_pem(raw):
    if b"-----BEGIN CERTIFICATE-----" in raw:
        return raw.decode()
    return ossl(["x509", "-inform", "DER", "-outform", "PEM"], raw).stdout.decode()


def main():
    os.makedirs(os.path.join(DATA, "crl"), exist_ok=True)
    os.makedirs(os.path.join(DATA, "cert"), exist_ok=True)
    certs = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n?", open(ANCHORS).read(), re.S)
    for url in ROOTS:
        try:
            certs.append(to_pem(get(url)[1]))
        except Exception as e:  # noqa: BLE001 - report and go on
            print(f"root {url}: {e}", file=sys.stderr)
    by_subject = {}

    def add_cert(pem):
        subj = ossl(["x509", "-noout", "-subject", "-nameopt", "RFC2253"], pem.encode()).stdout.decode().strip()
        fp = ossl(["x509", "-noout", "-fingerprint", "-sha256"], pem.encode()).stdout.decode().strip().split("=")[-1]
        path = os.path.join(DATA, "cert", fp.replace(":", "")[:16] + ".pem")
        open(path, "w").write(pem)
        by_subject.setdefault(subj, set()).add(path)

    for pem in certs:
        add_cert(pem)

    pairs, missing = [], []
    for s in json.load(open(os.path.join(HERE, "sources.json"))):
        path = os.path.join(DATA, "crl", s["id"] + ".crl")
        via = "ac"
        try:
            status, body = get(s["url"])
        except Exception as e:  # noqa: BLE001
            try:
                key, body = from_collector(s["id"])
                status, via = 200, "collector:" + key
            except Exception as e2:  # noqa: BLE001
                missing.append({"id": s["id"], "url": s["url"], "error": f"{str(e)[:80]}; collector: {str(e2)[:60]}"})
                continue
        if b"-----BEGIN X509 CRL-----" in body:
            body = ossl(["crl", "-outform", "DER"], body).stdout
        info = ossl(["crl", "-inform", "DER", "-noout", "-issuer", "-nameopt", "RFC2253"], body)
        if info.returncode != 0:
            missing.append({"id": s["id"], "url": s["url"], "error": f"HTTP {status}, not a CRL"})
            continue
        open(path, "wb").write(body)
        issuer = info.stdout.decode().strip().replace("issuer=", "subject=", 1)
        text = ossl(["crl", "-inform", "DER", "-noout", "-text"], body).stdout.decode(errors="replace")
        if issuer not in by_subject:  # retired AC: try the CRL's Authority Information Access (caIssuers, .p7b)
            for aia in re.findall(r"CA Issuers - URI:(\S+)", text):
                try:
                    p7 = get(aia)[1]
                except Exception as e:  # noqa: BLE001
                    print(f"AIA {aia}: {e}", file=sys.stderr)
                    continue
                form = "PEM" if p7.startswith(b"-----") else "DER"
                for pem in re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n?", ossl(["pkcs7", "-inform", form, "-print_certs"], p7).stdout.decode(), re.S):
                    add_cert(pem)
        alg = re.search(r"Signature Algorithm: (\S+)", text).group(1)
        pairs.append({"id": s["id"], "ac": s["ac"], "kind": s["kind"], "crl": path, "bytes": len(body),
                      "entries": text.count("Serial Number:"), "algorithm": alg, "via": via, "issuers": sorted(by_subject.get(issuer, []))})
    out = {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "pairs": pairs, "missing": missing}
    json.dump(out, open(os.path.join(DATA, "pairs.json"), "w"), indent=1)
    print(f"{len(pairs)} CRLs, {len(missing)} unreachable, {sum(1 for p in pairs if not p['issuers'])} without issuer certificate")


if __name__ == "__main__":
    main()
