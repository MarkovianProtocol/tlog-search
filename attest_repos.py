#!/usr/bin/env python3
"""Attest the head commit of every repo in an org, as served by the host.

git_attest.py records a commit from a local clone. This records what the host
served, which is the thing that can later disagree with itself: a force-push, a
rewritten date, or a different history shown to a different reader.

So the observation is deliberately of the host's answer, not of our disk.

    python3 attest_repos.py --org MarkovianProtocol --out leaves/

Uses the `gh` CLI for the API. Writes one leaf per repo; submits nothing.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import jcs

CLAIM_TYPE = "https://markovianprotocol.com/claim/git-commit/v1"


def gh(*args):
    r = subprocess.run(["gh"] + list(args), capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("gh %s failed: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--issuer", default="did:web:markovianprotocol.com")
    ap.add_argument("--limit", type=int, default=100)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    repos = json.loads(gh("repo", "list", a.org, "--limit", str(a.limit),
                          "--json", "name,defaultBranchRef,isFork,isArchived"))
    made = skipped = 0
    for r in sorted(repos, key=lambda x: x["name"]):
        if r.get("isFork"):
            skipped += 1
            continue
        ref = (r.get("defaultBranchRef") or {}).get("name")
        if not ref:
            skipped += 1
            continue
        full = "%s/%s" % (a.org, r["name"])
        try:
            c = json.loads(gh("api", "repos/%s/commits/%s" % (full, ref)))
        except SystemExit:
            skipped += 1
            continue
        v = c.get("commit", {}).get("verification") or {}
        leaf = {
            "claim_type": CLAIM_TYPE,
            "issuer": a.issuer,
            "subject": "git:github.com/%s@%s" % (full, c["sha"]),
            "commit": {
                "tree": c["commit"]["tree"]["sha"],
                "parents": [p["sha"] for p in c.get("parents", [])],
                "author_date": c["commit"]["author"]["date"],
                "committer_date": c["commit"]["committer"]["date"],
            },
            "signature": {
                "verified": bool(v.get("verified")),
                "reason": v.get("reason", "unknown"),
                "signer": (c["commit"]["author"] or {}).get("email", ""),
            },
            "observed": {
                "via": "github.com REST API",
                "ref": ref,
            },
        }
        path = os.path.join(a.out, "%s.leaf" % r["name"])
        with open(path, "wb") as fh:
            fh.write(jcs.encode(leaf))
        made += 1
        print("  %-28s %s  sig=%s" % (r["name"], c["sha"][:12],
                                      leaf["signature"]["reason"]))
    print("\n%d leaf/leaves written to %s, %d skipped (forks or no default branch)"
          % (made, a.out, skipped))
    print("Nothing submitted. These record what github.com served just now; a "
          "later")
    print("force-push or rewritten date is what they exist to contradict.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
