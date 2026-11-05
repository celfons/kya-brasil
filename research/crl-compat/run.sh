#!/bin/sh
# Runs every library over data/pairs.json (made by fetch.py) and writes data/results.jsonl, then the report.
set -eu
cd "$(dirname "$0")"
out=data/results.jsonl
: > "$out"
python3 -I run_openssl_py.py data/pairs.json openssl >> "$out"
python3 -I run_openssl_py.py data/pairs.json python >> "$out"
(cd go && go run . ../data/pairs.json) >> "$out"
npx tsx run-js.mjs data/pairs.json >> "$out"
python3 -I report.py data/pairs.json "$out"
