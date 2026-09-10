#!/usr/bin/env python3
"""Watch a set of Hugging Face models and log what changed.

Two failure modes to avoid, pulling in opposite directions.

Log every observation every run and the log fills with thousands of identical
leaves a year, which buries the few that matter and inflates a log that is
already short of issuers who are not us.

Log only changes and silence proves nothing: a model with no leaf might be
unchanged, or might never have been observed, and nothing distinguishes those.

So each run writes one digest leaf covering the whole observation set -- the
count and a hash over every model's state -- and a detail leaf only for models
that moved. Silence is then meaningful, because the digest says the run happened
and how many it covered, and a changed model always has its own leaf.

    python3 hf_watch.py --models models.txt --state state.json --submit

Stdlib only.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import jcs
import hf_attest

DIGEST_TYPE = "https://markovianprotocol.com/claim/hf-watch-digest/v1"
LOG_LOCAL = "http://127.0.0.1:8098"
TOKEN = os.path.expanduser("~/.secrets/log_admin_token")


def submit(blob):
    token = open(TOKEN).read().strip()
    req = urllib.request.Request(LOG_LOCAL + "/add-leaf", data=blob, method="POST",
                                 headers={"Authorization": "Bearer " + token,
                                          "Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode().strip()


def fingerprint(leaf):
    """The part of an observation that, if it changes, is worth its own leaf."""
    return {
        "sha": leaf["model"]["sha"],
        "card_sha256": leaf["card"]["sha256"],
        "gated": leaf["model"]["gated"],
        "private": leaf["model"]["private"],
        "disabled": leaf["model"]["disabled"],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--issuer", default="did:web:markovianprotocol.com")
    ap.add_argument("--submit", action="store_true")
    a = ap.parse_args()

    with open(a.models) as fh:
        ids = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    prev = {}
    if os.path.exists(a.state):
        with open(a.state) as fh:
            prev = json.load(fh)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    observed, changed, failed = {}, [], []
    for mid in ids:
        try:
            leaf = hf_attest.attest(mid, a.issuer)
        except Exception as e:
            failed.append(mid)
            print("  %-44s FAILED %r" % (mid, e))
            continue
        fp = fingerprint(leaf)
        observed[mid] = fp
        was = prev.get(mid)
        if was is None:
            print("  %-44s first observation" % mid)
        elif was != fp:
            deltas = {k: [was.get(k), fp[k]] for k in fp if was.get(k) != fp[k]}
            print("  %-44s CHANGED %s" % (mid, json.dumps(deltas)[:90]))
            leaf["changed_from"] = was
            changed.append(leaf)
        # unchanged models are covered by the digest, not by their own leaf

    # One digest per run, so a quiet run is still on the record.
    body = jcs.encode({"models": observed})
    digest = {
        "claim_type": DIGEST_TYPE,
        "issuer": a.issuer,
        "subject": "hf:watch@%s" % now,
        "observed_at": now,
        "count": len(observed),
        "failed": sorted(failed),
        "set_sha256": hashlib.sha256(body).hexdigest(),
        "changed": sorted(l["model"]["id"] for l in changed),
    }

    leaves = [jcs.encode(digest)] + [jcs.encode(l) for l in changed]
    print("\n%d observed, %d changed, %d failed -> %d leaf/leaves"
          % (len(observed), len(changed), len(failed), len(leaves)))

    if a.submit:
        for blob in leaves:
            try:
                size = submit(blob)
                print("  submitted -> tree size %s" % size)
            except Exception as e:
                print("  SUBMIT FAILED %r" % e)
                return 1
    else:
        print("  (not submitted; pass --submit)")

    tmp = a.state + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(observed, fh, indent=1, sort_keys=True)
    os.replace(tmp, a.state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
