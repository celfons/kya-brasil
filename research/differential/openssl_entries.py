"""What OpenSSL reads in each CRL of data/crl: the two dates and every entry (serial, revocation date, reason).

Usage: python3 -I openssl_entries.py   (writes data/openssl/<source>.json and data/openssl/version.txt)
"""
import json
import os
import subprocess
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CRL = os.path.join(HERE, "data", "crl")
OUT = os.path.join(HERE, "data", "openssl")
# The names `openssl crl -text` prints for the reasonCode of RFC 5280, 5.3.1.
REASONS = {"Unspecified": 0, "Key Compromise": 1, "CA Compromise": 2, "Affiliation Changed": 3, "Superseded": 4,
           "Cessation Of Operation": 5, "Certificate Hold": 6, "Remove From CRL": 8, "Privilege Withdrawn": 9,
           "AA Compromise": 10}


def when(text):
    return datetime.strptime(" ".join(text.split()), "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read(path):
    text = subprocess.run(["openssl", "crl", "-inform", "DER", "-in", path, "-noout", "-text"], check=True, capture_output=True, text=True).stdout
    out = {"this_update": None, "next_update": None, "entries": []}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("Last Update:"):
            out["this_update"] = when(s.split(":", 1)[1])
        elif s.startswith("Next Update:") and "NONE" not in s:
            out["next_update"] = when(s.split(":", 1)[1])
        elif s.startswith("Serial Number:"):
            out["entries"].append([s.split(":", 1)[1].strip().lower().lstrip("0") or "0", None, None])
        elif s.startswith("Revocation Date:"):
            out["entries"][-1][1] = when(s.split(":", 1)[1])
        elif s.startswith("X509v3 CRL Reason Code:") and out["entries"]:
            out["entries"][-1][2] = REASONS[lines[i + 1].strip()]
    if out["this_update"] is None or any(e[1] is None for e in out["entries"]):
        raise SystemExit(f"error: {path}: could not read the output of openssl")
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    names = sorted(n for n in os.listdir(CRL) if n.endswith(".crl"))
    total = 0
    for name in names:
        d = read(os.path.join(CRL, name))
        total += len(d["entries"])
        with open(os.path.join(OUT, name[:-4] + ".json"), "w", encoding="utf-8") as f:
            json.dump(d, f)
    version = subprocess.run(["openssl", "version"], check=True, capture_output=True, text=True).stdout.strip()
    with open(os.path.join(OUT, "version.txt"), "w", encoding="utf-8") as f:
        f.write(version + "\n")
    print(f"{version}: {len(names)} CRLs, {total} entries")


if __name__ == "__main__":
    main()
