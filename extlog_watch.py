#!/usr/bin/env python3
"""Record what an external party serves, and what its own log says.

Subjects are in logs.json. Each is a party that keeps a hash log in storage it
controls itself, and says so. F-Droid's btlog README, in its own words:

    "This is stored in a git repo, which serves as an imperfect append-only
     storage mechanism."

and the F-Droid security model states the missing piece:

    "In order to defend against an attacker that holds the signing keys for the
     app repository, there must be a trustworthy source of information to
     compare against."

A git repo the publisher owns can be force-pushed, and a mirror can serve one
index to one reader and another to the next. Neither is fixed by signing the
index better.

Dralvia's README asks for this outright: "If you care, clone this repository
regularly." This is that, on a schedule, by someone who is not them.

Each run records the digests of a subject's artifacts as served to us, paired
with the heads of its own logs at that moment. If either is ever rewritten, an
independently held record of the pair disagrees.

This is an observation of a public artifact. It publishes nothing of theirs that
was not already public, and asserts nothing about their conduct.

    python3 extlog_watch.py --logs logs.json --state state.json --submit

Stdlib only.
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import jcs

CLAIM_TYPE = "https://markovianprotocol.com/claim/external-log-observation/v1"
DIGEST_TYPE = "https://markovianprotocol.com/claim/fdroid-watch-digest/v1"
LOG_LOCAL = "http://127.0.0.1:8098"
TOKEN = os.path.expanduser("~/.secrets/log_admin_token")

def fetch(url, expect_length=True):
    """Read the whole body, and refuse a short one.

    index-v2.json is ~59MB. A truncated read hashes cleanly and looks like the
    publisher changed something, which is exactly the false alarm this tool must
    not raise -- it happened once during development, against a 25s timeout, and
    was briefly reported as F-Droid behaviour when it was our own bug.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "markovian-fdroid-watch/1"})
    with urllib.request.urlopen(req, timeout=300) as r:
        declared = r.headers.get("Content-Length")
        body = r.read()
    if expect_length and declared is not None and len(body) != int(declared):
        raise IOError("short read for %s: got %d of %s bytes"
                      % (url, len(body), declared))
    return body


def btlog_head(url, host):
    """Head commit of a log. Unauthenticated on both hosts; one call a day each."""
    try:
        c = json.loads(fetch(url, expect_length=False))
    except Exception:
        return None
    if not c:
        return None
    if host == "gitlab":
        return {"sha": c[0]["id"], "date": c[0]["committed_date"]}
    return {"sha": c[0]["sha"], "date": c[0]["commit"]["committer"]["date"]}


def observe(subjects):
    out = {}
    for sub in subjects:
        rec = {"artifacts": {}, "logs": {}}
        for name, url in sub.get("artifacts", []):
            b = fetch(url)
            rec["artifacts"][name] = {"sha256": hashlib.sha256(b).hexdigest(),
                                      "bytes": len(b)}
        for name, host, url in sub.get("logs", []):
            h = btlog_head(url, host)
            if h:
                rec["logs"][name] = h
        out[sub["name"]] = rec
    return out


def submit(blob):
    token = open(TOKEN).read().strip()
    req = urllib.request.Request(LOG_LOCAL + "/add-leaf", data=blob, method="POST",
                                 headers={"Authorization": "Bearer " + token,
                                          "Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode().strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--logs", required=True, help="logs.json")
    ap.add_argument("--state", required=True)
    ap.add_argument("--issuer", default="did:web:markovianprotocol.com")
    ap.add_argument("--submit", action="store_true")
    a = ap.parse_args()

    with open(a.logs) as fh:
        subjects = json.load(fh)["subjects"]
    prev = {}
    if os.path.exists(a.state):
        with open(a.state) as fh:
            prev = json.load(fh)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    obs = observe(subjects)

    changed = []
    for sname, rec in sorted(obs.items()):
        was = prev.get(sname, {})
        print("%s" % sname)
        for kind in ("artifacts", "logs"):
            for name, v in sorted(rec[kind].items()):
                key = "sha256" if kind == "artifacts" else "sha"
                old = (was.get(kind) or {}).get(name, {}).get(key)
                new = v[key]
                if old is None:
                    mark = "first"
                elif old == new:
                    mark = "unchanged"
                else:
                    mark = "CHANGED" if kind == "artifacts" else "advanced"
                    changed.append("%s/%s" % (sname, name))
                print("  %-46s %s  %s" % (name[:46], new[:16], mark))

    leaf = {
        "claim_type": CLAIM_TYPE,
        "issuer": a.issuer,
        "subject": "extlog:watch@%s" % now,
        "observed_at": now,
        "subjects": obs,
        "changed": sorted(changed),
        "observed_via": "direct fetch, api.github.com, gitlab.com/api/v4",
        "note": "digests of each subject's artifacts as served, paired with the "
                "heads of the hash logs that subject keeps in storage it controls",
    }
    blob = jcs.encode(leaf)
    print("\nleaf %d bytes, %d change(s)" % (len(blob), len(changed)))
    if a.submit:
        print("  submitted -> tree size %s" % submit(blob))
    else:
        print("  (not submitted; pass --submit)")

    tmp = a.state + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obs, fh, indent=1, sort_keys=True)
    os.replace(tmp, a.state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
