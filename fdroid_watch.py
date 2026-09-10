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
# Each log and the artifacts it actually covers. The pairing matters: an early
# version of this file paired f-droid.org's index with guardianproject's log,
# which is the log for guardianproject.info/fdroid -- a different repository.
# A record that pairs the wrong two things is worse than no record.
BTLOGS = [
    # canonical log for the f-droid.org repo, on GitLab
    ("fdroid/f-droid.org-transparency-log", "gitlab",
     "https://gitlab.com/api/v4/projects/fdroid%2Ff-droid.org-transparency-log"
     "/repository/commits?per_page=1"),
    # guardianproject.info/fdroid -- a different app repo, its own log
    ("guardianproject/binary_transparency_log", "github",
     "https://api.github.com/repos/guardianproject/binary_transparency_log"
     "/commits?per_page=1"),
    # these two log third-party binaries: Google's Android SDK, and Gradle
    ("f-droid/android-sdk-transparency-log", "github",
     "https://api.github.com/repos/f-droid/android-sdk-transparency-log"
     "/commits?per_page=1"),
    ("f-droid/gradle-transparency-log", "github",
     "https://api.github.com/repos/f-droid/gradle-transparency-log"
     "/commits?per_page=1"),
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


def observe():
    out = {"artifacts": {}, "btlogs": {}}
    for name, url in ARTIFACTS:
        b = fetch(url)
        out["artifacts"][name] = {"sha256": hashlib.sha256(b).hexdigest(),
                                  "bytes": len(b)}
    for name, host, url in BTLOGS:
        h = btlog_head(url, host)
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
        "observed": {"via": "https://f-droid.org/repo/, api.github.com, gitlab.com/api/v4",
                     "note": "digest of the f-droid.org index as served, paired with the "
                             "heads of four publisher-run git transparency logs at the "
                             "same moment; the first of those is the one covering this index"},
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
