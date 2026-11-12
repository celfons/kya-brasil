"""
Which bytes a result was computed from.

Every simulation records, under "inputs", the SHA-256 of each file in data/ as it was when the run started, and of
the result files it reads. manifest.py then checks that the results of a cut were all computed from the data/ that
is there now. The list is wider than what each script opens, on purpose: a file left out by mistake would be a hole,
and in a cut everything is regenerated together.

The rule comes from the test cut of 7 November 2026. data/availability.json was a day older than the other inputs,
the committed results had been computed from a newer copy that was never committed, and nothing compared the two.
"""
import hashlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def data_files():
    return sorted(n for n in os.listdir(DATA) if os.path.isfile(os.path.join(DATA, n)) and not n.startswith("."))


def stamp(*results):
    """{"data/<name>": sha256} for every file in data/, plus {"<result>": sha256} for the result files named."""
    out = {"data/" + n: sha256(os.path.join(DATA, n)) for n in data_files()}
    out.update({n: sha256(os.path.join(HERE, n)) for n in results})
    return out
