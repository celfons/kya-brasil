"""
Measured publication delays of end-user revocations, from the public ICP-Brasil CRL collector, for
simulate_measured_delay.py.

    python3 -I fetch_delays.py   # standard library only; writes data/delays.json

For each end-user CRL, the collector reports delays_h: for every revocation it saw appear, the thisUpdate of the first
collected CRL that contains it minus the revocationDate the AC recorded. That is the time from the AC registering a
revocation to a CRL that lists it, i.e. the wait for the next CRL. EXPLORATORY: the window is as long as the collection
so far, and only revocations registered after the collection started can be measured.
"""
import json
import os
import re
import urllib.parse
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "delays.json")
COLLECTOR = "https://kya-icp-collector.marcelfons.workers.dev"
SOURCE_ID = re.compile(r"^[a-z0-9-]{1,80}$")


def get(path):
    req = urllib.request.Request(COLLECTOR + path, headers={"User-Agent": "kya-brasil-research/1.0"})
    for i in range(4):  # the collector sits behind a CDN that now and then resets a connection
        try:
            with urllib.request.urlopen(req, timeout=180) as r:  # fixed host
                return json.load(r)
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            if i == 3:
                raise
            print(f"warning: {path}: {e}; retrying in {2 ** i} s", file=sys.stderr)
            time.sleep(2 ** i)


def main():
    summary = get("/api/summary")
    out = {"collector": COLLECTOR, "summary_generated_at": summary["generated_at"],
           "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "sources": {}}
    for s in summary["sources"]:
        if s["kind"] != "usuario-final" or not s.get("measured_delays") or not SOURCE_ID.match(s["source"]):
            continue
        d = get("/api/source/" + urllib.parse.quote(s["source"], safe=""))
        delays = [float(x) for x in d.get("delays_h") or [] if x is not None and x >= 0]
        out["sources"][s["source"]] = {"ac": s["ac"], "entries": s["entries"], "delays_h": delays}
        print(s["source"], len(delays), "delays")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
