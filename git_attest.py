#!/usr/bin/env python3
"""Turn a signed git commit into a claim a log can hold.

A commit signature says who. It does not say when, and it does not say this is
the only version published:

  - `author date` and `committer date` are set by whoever makes the commit, and
    the signature covers those chosen values, so a signature attests a time its
    own signer picked.
  - a signed commit can be force-pushed away and replaced by another signed
    commit, and nothing in either signature reveals that.
  - a host can serve one history to one reader and another to another; both
    verify.

None of those can be fixed by signing harder. They need a record kept somewhere
the committer does not control, at a time the committer does not choose.

This emits that record. It states what was observed, not that the commit is
good -- an observation of a bad signature is still worth logging.

    python3 git_attest.py --repo . --rev HEAD
    python3 git_attest.py --repo . --rev HEAD --issuer did:web:example.com

Stdlib only, no network.
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


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo] + list(args),
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("git %s failed: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout.rstrip("\n")


def remote_subject(repo, sha):
    """A subject a stranger can resolve: host/owner/repo@sha."""
    try:
        url = git(repo, "config", "--get", "remote.origin.url")
    except SystemExit:
        return "git:local@" + sha
    url = url.strip()
    for prefix in ("https://", "git@", "ssh://git@"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    url = url.replace(":", "/", 1) if url.startswith("github.com") is False else url
    if url.endswith(".git"):
        url = url[:-4]
    return "git:%s@%s" % (url, sha)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--issuer", default="did:web:markovianprotocol.com")
    ap.add_argument("--out", help="write the leaf bytes here")
    a = ap.parse_args()

    sha = git(a.repo, "rev-parse", a.rev)
    fields = git(a.repo, "show", "-s", "--format=%T%n%P%n%aI%n%cI%n%G?%n%GS%n%GK", sha)
    tree, parents, adate, cdate, status, signer, keyid = (
        fields.split("\n") + [""] * 7)[:7]

    # G good, B bad, U good-but-unknown-trust, N none, E cannot check.
    verified = status == "G"
    leaf = {
        "claim_type": CLAIM_TYPE,
        "issuer": a.issuer,
        "subject": remote_subject(a.repo, sha),
        "commit": {
            "tree": tree,
            "parents": [p for p in parents.split() if p],
            "author_date": adate,
            "committer_date": cdate,
        },
        "signature": {
            "status": status,
            "verified": verified,
            "signer": signer,
            "key": keyid,
        },
    }
    blob = jcs.encode(leaf)
    if a.out:
        with open(a.out, "wb") as fh:
            fh.write(blob)
        print("wrote %s (%d bytes)" % (a.out, len(blob)))
    print(blob.decode())
    print()
    print("What logging this adds: the dates above were chosen by the committer, "
          "and the")
    print("signature covers the values they chose. Once this leaf is in a "
          "witnessed log,")
    print("the commit cannot later be given an earlier date, replaced by a "
          "force-push, or")
    print("shown to one reader and not another, without the log disagreeing.")
    if not verified:
        print()
        print("Signature status is %r, not 'G'. Logged as observed -- an "
              "unverified commit" % status)
        print("is a fact worth recording, not a reason to refuse.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
