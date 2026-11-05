#!/bin/sh
# Runs every library over data/pairs.json (made by fetch.py) and writes data/results.jsonl, then the report.
set -eu
cd "$(dirname "$0")"
out=data/results.jsonl
: > "$out"
python3 -I run_openssl_py.py openssl >> "$out"
python3 -I run_openssl_py.py python >> "$out"
(cd go && go run .) >> "$out"
pnpm exec tsx run-js.mjs >> "$out"  # the tsx pinned in package.json; installs nothing
python3 -I report.py
