"""Downloads the current CRL of every source in sources.json (a snapshot of kya-icp/sources.json) and the ICP-Brasil
root certificates, then pairs each CRL with the certificates whose subject equals its issuer.

Writes data/crl/<sha256 prefix>.crl, data/cert/<sha256 prefix>.pem and data/pairs.json, whose paths are relative to data/.
Run with python3 -I from this directory.

CRLs and the ITI roots are served over plain HTTP: RFC 5280 distribution points are HTTP, and ITI's HTTPS uses the
ICP-Brasil chain, which public trust stores lack. A CRL is protected by its signature, which is what this study
checks; a root is accepted only if its SHA-256 is pinned below (the same roots as the reviewed anchors bundle).
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
ANCHORS = os.path.join(HERE, "..", "..", "anchors", "icp-brasil.pem")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")  # same rule as the kya-icp collector
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----\n?", re.S)
# The kya-icp collector keeps every CRL version it fetched (R2): used when an AC's server does not answer this run.
COLLECTOR = os.environ.get("KYA_ICP_COLLECTOR", "https://kya-icp-collector.marcelfons.workers.dev")
# Plain HTTP on purpose (see the module docstring): each root is accepted only with the SHA-256 pinned below.
ROOT_URL = "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv{}.crt"  # NOSONAR
ROOT_SHA256 = {
    2: "fb47d92a9909fd4fa9bec02737543e1f3514ced747407a8d9cfa397b0915067c",
    3: "1226ebf38af7335ffb346de68840d5652d9be7413a65b989375edac6a7f16172",
    4: "f0c15afd258fb674e7a96e1a50ff873149364b9ec70d4d93c7a9f1eb6060d020",
    5: "caa53fc6091c6951887c976e378f6ef89aa6377c55d97b6475422b71ed7e9b17",
    6: "3bdb9b509352f1d3d71c2bf64d9a38a4e6cebda27809d77f7ac476cbde6e314a",
    7: "5657e70580eb678983f3ed7dfce091d84cae6549389a47fccda8d0e4dc2cf576",
    8: "cd5406f61a8d5d08a3797da044be669c555c2d8b821d67577f0a2ce3a1a277e1",
    9: "cdd1149dcfc137c4c34fa844cf592cfbfea05cb13b770ad5e1f0c7fc8c9c43bf",
    10: "6e0bff069a26994c15de2c4888cc54af84882e5495b7fbf66be9ccffec7489f6",
    11: "1406710058180fa4081aab3f246f1702429c552a11fa3143b84c88cb3ab8e5e7",
    12: "d8478e37ce19c690cf657381e68fe600e4e1a042536830f06847e03e554c4b01",
}


def checked_url(url):
    """Only http(s) URLs with a host name and no credentials: sources.json is data, not a list of arbitrary targets."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError(f"refusing URL {url!r}")
    if re.fullmatch(r"[0-9.]+|\[.*\]|localhost", u.hostname):
        raise ValueError(f"refusing URL {url!r}: not a public host name")
    return url


def get(url, timeout=90):
    # The URL comes from sources.json or a CRL's caIssuers, and checked_url limits it to http(s) on a public host.
    with urllib.request.urlopen(checked_url(url), timeout=timeout) as r:  # NOSONAR
        return r.status, r.read()


def ossl(args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True)


def from_collector(source_id):
    """Latest copy of `source_id` in the collector, fetched with the curl CLI (the collector refuses urllib's agent)."""
    def curl(path):
        return subprocess.run(["curl", "-sS", "--fail", "--max-time", "120", checked_url(COLLECTOR + path)], capture_output=True, check=True).stdout
    files = json.loads(curl("/api/files/" + urllib.parse.quote(source_id)))["files"]
    if not files:
        raise RuntimeError("collector has no copy")
    key = max(files, key=lambda f: f["uploaded"])["key"]
    return key, curl("/files/" + urllib.parse.quote(key))


class Certs:
    """Issuer certificates on disk, by RFC 2253 subject."""

    def __init__(self):
        self.by_subject = {}

    def add(self, pem):
        subj = ossl(["x509", "-noout", "-subject", "-nameopt", "RFC2253"], pem.encode()).stdout.decode().strip()
        der = ossl(["x509", "-outform", "DER"], pem.encode()).stdout
        name = hashlib.sha256(der).hexdigest()[:16] + ".pem"
        with open(os.path.join(DATA, "cert", name), "w") as f:  # name is a hash of the certificate
            f.write(pem)
        self.by_subject.setdefault(subj, set()).add(name)

    def add_roots(self):
        for v, sha in ROOT_SHA256.items():
            try:
                raw = get(ROOT_URL.format(v))[1]
            except Exception as e:  # noqa: BLE001 - report and go on
                print(f"root v{v}: {e}", file=sys.stderr)
                continue
            der = raw if not raw.startswith(b"-----") else ossl(["x509", "-outform", "DER"], raw).stdout
            if hashlib.sha256(der).hexdigest() != sha:
                print(f"root v{v}: SHA-256 does not match the pinned value, ignored", file=sys.stderr)
                continue
            self.add(ossl(["x509", "-inform", "DER", "-outform", "PEM"], der).stdout.decode())

    def add_from_aia(self, text):
        """Certificates from the CRL's caIssuers (.p7b): retired ACs are not in the anchors bundle."""
        for aia in re.findall(r"CA Issuers - URI:(\S+)", text):
            try:
                p7 = get(aia)[1]
            except Exception as e:  # noqa: BLE001
                print(f"AIA {aia}: {e}", file=sys.stderr)
                continue
            form = "PEM" if p7.startswith(b"-----") else "DER"
            for pem in PEM_RE.findall(ossl(["pkcs7", "-inform", form, "-print_certs"], p7).stdout.decode()):
                self.add(pem)


def download(source):
    """(DER CRL, how it was obtained); raises when neither the AC nor the collector has it."""
    try:
        body = get(source["url"])[1]
        via = "ac"
    except Exception as e:  # noqa: BLE001
        try:
            key, body = from_collector(source["id"])
        except Exception as e2:  # noqa: BLE001
            raise RuntimeError(f"{str(e)[:80]}; collector: {str(e2)[:60]}") from e2
        via = "collector:" + key
    if b"-----BEGIN X509 CRL-----" in body:
        body = ossl(["crl", "-outform", "DER"], body).stdout
    return body, via


def describe(source, body, via, certs):
    """The pairs.json record of one CRL; raises when the body is not a CRL."""
    info = ossl(["crl", "-inform", "DER", "-noout", "-issuer", "-nameopt", "RFC2253"], body)
    if info.returncode != 0:
        raise RuntimeError("not a CRL")
    # Content-addressed, like the certificates: no part of the file name comes from sources.json.
    name = hashlib.sha256(body).hexdigest()[:16] + ".crl"
    with open(os.path.join(DATA, "crl", name), "wb") as f:
        f.write(body)
    issuer = info.stdout.decode().strip().replace("issuer=", "subject=", 1)
    text = ossl(["crl", "-inform", "DER", "-noout", "-text"], body).stdout.decode(errors="replace")
    if issuer not in certs.by_subject:
        certs.add_from_aia(text)
    return {"id": source["id"], "ac": source["ac"], "kind": source["kind"], "crl": name, "bytes": len(body),
            "entries": text.count("Serial Number:"), "algorithm": re.search(r"Signature Algorithm: (\S+)", text).group(1),
            "via": via, "issuers": sorted(certs.by_subject.get(issuer, []))}


def main():
    os.makedirs(os.path.join(DATA, "crl"), exist_ok=True)
    os.makedirs(os.path.join(DATA, "cert"), exist_ok=True)
    certs = Certs()
    with open(ANCHORS) as f:
        for pem in PEM_RE.findall(f.read()):
            certs.add(pem)
    certs.add_roots()
    with open(os.path.join(HERE, "sources.json")) as f:
        sources = json.load(f)
    pairs, missing = [], []
    for s in sources:
        if not ID_RE.match(s.get("id", "")):
            raise ValueError(f"source id {s.get('id')!r} does not match {ID_RE.pattern}")
        try:
            pairs.append(describe(s, *download(s), certs))
        except Exception as e:  # noqa: BLE001
            missing.append({"id": s["id"], "url": s["url"], "error": str(e)[:160]})
    out = {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "pairs": pairs, "missing": missing}
    with open(os.path.join(DATA, "pairs.json"), "w") as f:
        json.dump(out, f, indent=1)
    print(f"{len(pairs)} CRLs, {len(missing)} unreachable, {sum(1 for p in pairs if not p['issuers'])} without issuer certificate")


if __name__ == "__main__":
    main()
