"""The CRLs of the cut, byte for byte, from the collector: the files fetch_measured.py named in measured.json.

Usage: python3 -I fetch.py   (writes data/crl/<source>.crl; data/ is not committed)
"""
import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MEASURED = os.path.join(HERE, "..", "freshness-sim", "data", "measured.json")
OUT = os.path.join(HERE, "data", "crl")
SOURCE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
KEY = re.compile(r"^lcr/[a-z0-9][a-z0-9-]{0,63}/[0-9TZ]+_([0-9a-f]{16})\.crl$")


def get(url):
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "kya-brasil-research"}), timeout=120) as r:
                return r.read()
        except OSError:
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)


def main():
    measured = json.load(open(MEASURED, encoding="utf-8"))
    os.makedirs(OUT, exist_ok=True)
    for source, v in sorted(measured["weekday_hour_sources"].items()):
        m = KEY.match(v["file"])
        if not SOURCE.match(source) or not m:
            raise SystemExit(f"error: unexpected source or key: {source!r} {v['file']!r}")
        path = os.path.join(OUT, source + ".crl")
        if not os.path.exists(path):
            der = get(measured["collector"] + "/files/" + urllib.parse.quote(v["file"]))
            if not hashlib.sha256(der).hexdigest().startswith(m.group(1)):
                raise SystemExit(f"error: {source}: the bytes do not have the SHA-256 the key names")
            with open(path, "wb") as f:
                f.write(der)
    print(f"{len(measured['weekday_hour_sources'])} CRLs of the cut of {measured['generated_at']} in data/crl")


if __name__ == "__main__":
    main()
