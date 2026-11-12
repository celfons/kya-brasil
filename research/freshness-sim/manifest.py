"""
The manifest of a cut: what every input and every result is, and whether they belong together.

    python3 -I manifest.py   # standard library only; after the fetches and the simulations; writes manifest.json

Two checks, and the run exits with 1 when either fails:
  - the inputs taken from the collector carry a date within WINDOW_H hours of the cut, which is the generated_at of
    data/measured.json. An input fetched on another day is from another cut;
  - every result was computed from the data/ that is there now: the SHA-256 each simulation recorded under "inputs"
    (provenance.py) equals the SHA-256 of the file today, for the files in data/ and for the results it read.
manifest.json lists the cut, the SHA-256 and the date of each input and the SHA-256 of each result. The paper
repository copies it with the data and refuses to generate numbers from files that do not match it.
"""
import json
import os
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I leaves the script directory out of sys.path
import provenance  # noqa: E402

WINDOW_H = 6.0
# Inputs read from the collector, and the field that dates the snapshot each one describes. The Pix and card series
# come from the Central Bank, are monthly or quarterly, and have no cut of their own: hashed, not dated.
DATED = {"measured.json": "generated_at", "flow.json": "fetched_at", "delays.json": "summary_generated_at",
         "availability.json": "summary_generated_at", "reasons.json": "fetched_at"}
RESULTS = ("results_measured.json", "results_measured_delay.json", "results_availability.json", "scenarios.json",
           "sensitivity.json")


def when(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    problems = []
    cut = load(os.path.join(provenance.DATA, "measured.json"))["generated_at"]
    inputs = {}
    for name in provenance.data_files():
        path = os.path.join(provenance.DATA, name)
        entry = {"sha256": provenance.sha256(path)}
        if name in DATED:
            entry["at"] = load(path)[DATED[name]]
            apart = abs((when(entry["at"]) - when(cut)).total_seconds()) / 3600
            if apart > WINDOW_H:
                problems.append(f"data/{name} is dated {entry['at']}, {apart:.0f} h from the cut ({cut}): it is from another cut")
        inputs["data/" + name] = entry
    results = {}
    for name in RESULTS:
        path = os.path.join(HERE, name)
        results[name] = {"sha256": provenance.sha256(path)}
        recorded = load(path).get("inputs")
        if not recorded:
            problems.append(f"{name} does not say what it was computed from: run its simulation again")
            continue
        for key, digest in recorded.items():
            other = os.path.join(HERE, key)
            now = inputs[key]["sha256"] if key in inputs else provenance.sha256(other) if os.path.isfile(other) else None
            if now != digest:
                problems.append(f"{name} was computed from another {key}: run its simulation again")
        missing = sorted(set(inputs) - set(recorded))
        if missing:
            problems.append(f"{name} was computed without {', '.join(missing)} in data/: run its simulation again")
    if problems:
        raise SystemExit("error: the cut is not consistent\n  " + "\n  ".join(problems))
    with open(os.path.join(HERE, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"cut": cut, "window_h": WINDOW_H, "inputs": inputs, "results": results}, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(json.dumps({"cut": cut, "inputs": len(inputs), "results": len(results)}))


if __name__ == "__main__":
    main()
