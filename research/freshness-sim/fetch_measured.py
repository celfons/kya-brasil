"""
Fetch the measured inputs of simulate_measured.py from the public ICP-Brasil CRL collector and write them under
data/ (fixed paths inside the repository; no command-line paths).

    python3 -I fetch_measured.py            # a new cut: the latest CRL of every source
    python3 -I fetch_measured.py --reread   # the same cut again: the files data/measured.json names

Writes:
  data/weekday_hour.csv   revocations per (weekday, hour) in Brasília time (UTC-3, no DST since 2019), counted
                          over the latest raw CRL of every end-user ("usuario-final") source;
  data/measured.json      monthly revocations of 2026, active certificates (ITI), CRL cadence per AC.
Needs `cryptography`. The collector rejects the default Python user agent, so requests send "curl/8".

No list is skipped: a CRL the package refuses is read by the DER walker of crl_entries.py, and one that neither
decodes stops the run. --reread exists because the collector never deletes a file: when a reader is fixed, the grid of
a cut is rebuilt from the same bytes, and the monthly counts, the ITI figure and the cadence of that cut are kept.
"""
import csv
import io
import json
import os
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
from collections import Counter
from datetime import timezone, datetime, timedelta

import re

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script directory out of sys.path
import crl_entries  # noqa: E402

BASE = "https://kya-icp-collector.marcelfons.workers.dev"
# Fixed paths, relative to this file (no command-line paths: nothing outside the repository is written).
DATA = os.path.join(HERE, "data")
UA = {"user-agent": "curl/8"}
BRT = timedelta(hours=-3)
DAYS = ["seg", "ter", "qua", "qui", "sex", "sab", "dom"]
KEY_TS = re.compile(r"/(\d{8}T\d{6}Z)_[0-9a-f]+\.crl$")


def reissue_interval(files):
    """Smallest gap between the thisUpdate of consecutive stored versions, in hours: the AC's reissue period.

    The mean gap would be wrong: the collector polls hourly, so an AC that reissues every 30 min is seen every other
    version, and the mean converges to the polling interval. None with fewer than two versions."""
    ts = sorted({datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ") for f in files if (m := KEY_TS.search(f["key"]))})
    gaps = [(b - a).total_seconds() / 3600.0 for a, b in zip(ts, ts[1:]) if b > a]
    return round(min(gaps), 3) if gaps else None


def get(path, attempts=4):
    """GET with retries: the collector sits behind a CDN that now and then resets a connection."""
    for i in range(attempts):
        try:
            with urllib.request.urlopen(urllib.request.Request(BASE + path, headers=UA), timeout=180) as r:
                return r.read()
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            if i == attempts - 1:
                raise
            print(f"warning: {path}: {e}; retrying in {2 ** i} s", file=sys.stderr)
            time.sleep(2 ** i)


def hours(a, b):
    def f(s):
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    return (f(b) - f(a)).total_seconds() / 3600.0


def snapshot():
    """A new cut: (measured.json without the grid, {source: key of its latest file})."""
    summary = json.loads(get("/api/summary"))
    uf = [s for s in summary["sources"] if s["kind"] == "usuario-final"]
    keys, reissue = {}, {}
    for s in uf:
        files = json.loads(get("/api/files/" + urllib.parse.quote(s["source"])))["files"]
        if not files:
            continue
        reissue[s["source"]] = reissue_interval(files)
        keys[s["source"]] = max(files, key=lambda f: f["key"])["key"]
    monthly = Counter()
    for r in csv.DictReader(io.StringIO(get("/api/monthly.csv").decode("utf-8"))):
        if r["tipo"] == "usuario-final" and r["mes"].startswith("2026-"):
            monthly[r["mes"]] += int(r["revogacoes"])
    iti = list(csv.DictReader(io.StringIO(get("/api/iti.csv").decode("utf-8"))))[-1]
    cadence = {
        s["source"]: {
            "ac": s["ac"], "last_this_update": s["last_this_update"], "next_update": s["next_update"],
            "validity_h": round(hours(s["last_this_update"], s["next_update"]), 3),
            "reissue_h": reissue.get(s["source"]),
            "entries": s["entries"], "entries_with_reason": s["entries_with_reason"],
        }
        for s in uf
    }
    out = {
        "generated_at": summary["generated_at"], "collector": BASE,
        "monthly_2026_usuario_final": dict(sorted(monthly.items())), "iti": iti,
        "cadence_usuario_final": cadence,
    }
    return out, keys


def profile(keys):
    """(weekday x hour grid in Brasília time, per-source record) over the entries of the files named in keys."""
    grid = Counter()
    per_source = {}
    for source, key in keys.items():
        entries, reader = crl_entries.decode(get("/files/" + urllib.parse.quote(key)), f"{source}: {key}")
        for rev, _ in entries:
            t = rev + BRT
            grid[(t.weekday(), t.hour)] += 1
        per_source[source] = {"file": key, "revocations": len(entries)}
        if reader != "cryptography":
            per_source[source]["reader"] = reader
    return grid, per_source


def main():
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, "measured.json")
    if "--reread" in sys.argv[1:]:
        with open(path, encoding="utf-8") as f:
            out = json.load(f)
        keys = {source: v["file"] for source, v in out["weekday_hour_sources"].items()}
    else:
        out, keys = snapshot()
    grid, per_source = profile(keys)
    with open(os.path.join(DATA, "weekday_hour.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["weekday", "dia", "hour_brt", "revocations"])
        for d in range(7):
            for h in range(24):
                w.writerow([d, DAYS[d], h, grid[(d, h)]])
    out["weekday_hour_sources"] = per_source
    out["weekday_hour_total"] = sum(grid.values())
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(json.dumps({"total": out["weekday_hour_total"], "monthly": out["monthly_2026_usuario_final"]}))


if __name__ == "__main__":
    main()
