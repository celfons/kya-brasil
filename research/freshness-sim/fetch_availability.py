"""
Timeline of the end-user CRLs as an hourly poller saw them, from the public ICP-Brasil CRL collector, for the
availability analysis (simulate_availability.py).

    python3 -I fetch_availability.py            # standard library only; writes data/availability.json
    python3 -I fetch_availability.py --reread   # the cut of data/measured.json again: its sources, versions up to it

For each end-user CRL still issued in 2026, the collector's file list gives every version it stored: the CRL's
thisUpdate (in the file name) and the moment the collector got it (uploaded). The validity of each version is the
source's nextUpdate - thisUpdate interval, read from the latest version (the same for every version of a source in the
data seen so far). A verifier polling as often as the collector (hourly) sees, at time t, the latest version uploaded
before t. EXPLORATORY: the window is as long as the collection so far, and a collector outage looks like an AC outage.

--reread rebuilds the timeline of a cut already taken: the sources and their validity come from data/measured.json,
and only the versions the collector had stored by that file's generated_at are kept. The collector never deletes a
version, so the timeline of a past cut can be read again at any time.
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
MEASURED = os.path.join(HERE, "data", "measured.json")
OUT = os.path.join(HERE, "data", "availability.json")
COLLECTOR = "https://kya-icp-collector.marcelfons.workers.dev"
SOURCE_ID = re.compile(r"^[a-z0-9-]{1,80}$")
KEY_TS = re.compile(r"/(\d{8}T\d{6}Z)_[0-9a-f]+\.crl$")


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


def iso(ts):
    return datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def hours(a, b):
    return (datetime.fromisoformat(b.replace("Z", "+00:00")) - datetime.fromisoformat(a.replace("Z", "+00:00"))).total_seconds() / 3600


def live():
    """(generated_at, [end-user sources of the collector's summary], no cut-off, now)."""
    summary = get("/api/summary")
    sources = [s for s in summary["sources"] if s["kind"] == "usuario-final"]
    return summary["generated_at"], sources, None, datetime.now(timezone.utc).isoformat(timespec="seconds")


def cut():
    """The same four values for the cut data/measured.json records; versions stored after it are left out."""
    with open(MEASURED, encoding="utf-8") as f:
        measured = json.load(f)
    sources = [{"source": k, **v} for k, v in measured["cadence_usuario_final"].items()]
    at = measured["generated_at"]
    return at, sources, at, at


def main():
    generated_at, sources, until, fetched_at = cut() if "--reread" in sys.argv[1:] else live()
    out = {"collector": COLLECTOR, "summary_generated_at": generated_at, "fetched_at": fetched_at, "sources": {}}
    for s in sources:
        if not (s.get("last_this_update") or "").startswith("2026") or not s.get("next_update"):
            continue
        sid = s["source"]
        if not SOURCE_ID.match(sid):
            continue
        files = get("/api/files/" + urllib.parse.quote(sid, safe=""))["files"]
        versions = []
        for f in files:
            m = KEY_TS.search(f["key"])
            if m and (until is None or f["uploaded"] <= until):
                versions.append({"this_update": iso(m.group(1)), "uploaded": f["uploaded"]})
        versions.sort(key=lambda v: v["uploaded"])
        out["sources"][sid] = {"ac": s["ac"], "entries": s["entries"],
                               "validity_h": round(hours(s["last_this_update"], s["next_update"]), 4),
                               "versions": versions}
        print(sid, len(versions), "versions", out["sources"][sid]["validity_h"], "h validity")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
