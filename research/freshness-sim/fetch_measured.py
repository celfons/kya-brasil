"""
Fetch the measured inputs of simulate_measured.py from the public ICP-Brasil CRL collector and write them under
data/ (fixed paths inside the repository; no command-line paths).

    python3 -I fetch_measured.py

Writes:
  data/weekday_hour.csv   revocations per (weekday, hour) in Brasília time (UTC-3, no DST since 2019), counted
                          over the latest raw CRL of every end-user ("usuario-final") source;
  data/measured.json      monthly revocations of 2026, active certificates (ITI), CRL cadence per AC.
Needs `cryptography`. The collector rejects the default Python user agent, so requests send "curl/8".
"""
import csv
import io
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter
from datetime import timezone, datetime, timedelta

import re

from cryptography import x509

BASE = "https://kya-icp-collector.marcelfons.workers.dev"
# Fixed paths, relative to this file (no command-line paths: nothing outside the repository is written).
HERE = os.path.dirname(os.path.abspath(__file__))
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


def get(path):
    with urllib.request.urlopen(urllib.request.Request(BASE + path, headers=UA), timeout=180) as r:
        return r.read()


def hours(a, b):
    def f(s):
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    return (f(b) - f(a)).total_seconds() / 3600.0


def main():
    os.makedirs(DATA, exist_ok=True)
    summary = json.loads(get("/api/summary"))
    uf = [s for s in summary["sources"] if s["kind"] == "usuario-final"]
    grid = Counter()
    per_source = {}
    reissue = {}
    for s in uf:
        files = json.loads(get("/api/files/" + urllib.parse.quote(s["source"])))["files"]
        if not files:
            continue
        reissue[s["source"]] = reissue_interval(files)
        key = max(files, key=lambda f: f["key"])["key"]
        try:
            crl = x509.load_der_x509_crl(get("/files/" + urllib.parse.quote(key)))
        except ValueError as e:
            # A CRL the cryptography library cannot decode (e.g. a signature algorithm it does not know) is skipped
            # with a warning, and the collector's own header parser still counts it in the aggregates.
            print(f"warning: {s['source']}: {key}: {e}", file=sys.stderr)
            per_source[s["source"]] = {"file": key, "revocations": None, "error": str(e)}
            continue
        n = 0
        for rc in crl:
            # cryptography >= 42 has revocation_date_utc; older versions give a naive UTC datetime.
            rev = rc.revocation_date_utc if hasattr(rc, "revocation_date_utc") else rc.revocation_date.replace(tzinfo=timezone.utc)
            t = rev + BRT
            grid[(t.weekday(), t.hour)] += 1
            n += 1
        per_source[s["source"]] = {"file": key, "revocations": n}
    with open(os.path.join(DATA, "weekday_hour.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["weekday", "dia", "hour_brt", "revocations"])
        for d in range(7):
            for h in range(24):
                w.writerow([d, DAYS[d], h, grid[(d, h)]])

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
        "cadence_usuario_final": cadence, "weekday_hour_sources": per_source,
        "weekday_hour_total": sum(grid.values()),
    }
    with open(os.path.join(DATA, "measured.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(json.dumps({"total": out["weekday_hour_total"], "monthly": out["monthly_2026_usuario_final"]}))


if __name__ == "__main__":
    main()
