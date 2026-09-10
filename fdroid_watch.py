#!/usr/bin/env python3
"""Record what f-droid.org serves, and what its own transparency log says.

F-Droid publishes a signed app index and keeps a binary transparency log of it.
That log's README describes itself, in its own words:

    "This is stored in a git repo, which serves as an imperfect append-only
     storage mechanism."

and the F-Droid security model states the missing piece:

    "In order to defend against an attacker that holds the signing keys for the
     app repository, there must be a trustworthy source of information to
     compare against."

A git repo the publisher owns can be force-pushed, and a mirror can serve one
index to one reader and another to the next. Neither is fixed by signing the
index better.

So each run records two things together: the digest of the index as served to
us, and the head commit of the transparency log at that moment. If either is
ever rewritten, an independently held record of the pair disagrees.

This is an observation of a public artifact. It publishes nothing of theirs that
was not already public, and asserts nothing about their conduct.

    python3 fdroid_watch.py --state state.json --submit

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

CLAIM_TYPE = "https://markovianprotocol.com/claim/fdroid-index/v1"
DIGEST_TYPE = "https://markovianprotocol.com/claim/fdroid-watch-digest/v1"
LOG_LOCAL = "http://127.0.0.1:8098"
TOKEN = os.path.expanduser("~/.secrets/log_admin_token")

ARTIFACTS = [
    ("f-droid.org/repo/entry.jar", "https://f-droid.org/repo/entry.jar"),
    ("f-droid.org/repo/index-v2.json", "https://f-droid.org/repo/index-v2.json"),
]
BTLOGS = [
    ("guardianproject/binary_transparency_log",
     "repos/guardianproject/binary_transparency_log/commits"),
]


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


def btlog_head(api_path):
    """Unauthenticated GitHub API. 60 requests/hour is ample for a daily run,
    and it keeps this stdlib-only rather than depending on the gh CLI."""
    try:
        c = json.loads(fetch("https://api.github.com/" + api_path + "?per_page=1",
                             expect_length=False))
    except Exception:
        return None
    if not c:
        return None
    return {"sha": c[0]["sha"], "date": c[0]["commit"]["committer"]["date"]}


def observe():
    out = {"artifacts": {}, "btlogs": {}}
    for name, url in ARTIFACTS:
        b = fetch(url)
        out["artifacts"][name] = {"sha256": hashlib.sha256(b).hexdigest(),
                                  "bytes": len(b)}
    for name, api in BTLOGS:
        h = btlog_head(api)
        if h:
            out["btlogs"][name] = h
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
    ap.add_argument("--state", required=True)
    ap.add_argument("--issuer", default="did:web:markovianprotocol.com")
    ap.add_argument("--submit", action="store_true")
    a = ap.parse_args()

    prev = {}
    if os.path.exists(a.state):
        with open(a.state) as fh:
            prev = json.load(fh)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    obs = observe()
    for name, v in obs["artifacts"].items():
        was = (prev.get("artifacts") or {}).get(name, {}).get("sha256")
        mark = "unchanged" if was == v["sha256"] else ("first" if was is None else "CHANGED")
        print("  %-32s %s  %s" % (name, v["sha256"][:16], mark))
    for name, v in obs["btlogs"].items():
        was = (prev.get("btlogs") or {}).get(name, {}).get("sha")
        mark = "unchanged" if was == v["sha"] else ("first" if was is None else "advanced")
        print("  %-32s %s  %s" % (name, v["sha"][:16], mark))

    leaf = {
        "claim_type": CLAIM_TYPE,
        "issuer": a.issuer,
        "subject": "fdroid:index@%s" % now,
        "observed_at": now,
        "artifacts": obs["artifacts"],
        "btlogs": obs["btlogs"],
        "observed": {"via": "https://f-droid.org/repo/ and api.github.com",
                     "note": "digest of the index as served, paired with the head of "
                             "the publisher's own transparency log at the same moment"},
    }
    blob = jcs.encode(leaf)
    print("\nleaf %d bytes" % len(blob))
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
