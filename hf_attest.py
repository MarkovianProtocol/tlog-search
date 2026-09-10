#!/usr/bin/env python3
"""Record what Hugging Face served for a model, and when.

The Hub already gives an author git history, so "the card said X at commit Y" is
answerable while the repo exists. Two things it does not give:

  - evidence that survives the repo. Models get gated, renamed, made private or
    pulled, and the history goes with them.
  - evidence independent of the Hub. A verdict the Hub computes is one the Hub
    can compute differently later; we watched exactly that happen on GitHub,
    where the same unchanged commit read `unknown_key` and then `valid`.

So this records the head commit and a digest of the card as served, at a time
the author does not pick, somewhere the Hub does not control.

It is not an accusation. It is the same instrument pointed at anyone who wants
their published claims to stay checkable, including at themselves.

    python3 hf_attest.py --model openai/whisper-large-v3 --out leaves/
    python3 hf_attest.py --models models.txt --out leaves/

Stdlib only.
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import jcs

CLAIM_TYPE = "https://markovianprotocol.com/claim/hf-model-card/v1"
API = "https://huggingface.co"


def get(path, binary=False):
    req = urllib.request.Request(API + path,
                                 headers={"User-Agent": "markovian-hf-attest/1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        b = r.read()
    return b if binary else json.loads(b)


def attest(model_id, issuer):
    meta = get("/api/models/%s" % model_id)
    sha = meta.get("sha")
    card_sha256 = None
    card_bytes = 0
    try:
        card = get("/%s/raw/%s/README.md" % (model_id, sha or "main"), binary=True)
        card_sha256 = hashlib.sha256(card).hexdigest()
        card_bytes = len(card)
    except urllib.error.HTTPError as e:
        card_sha256 = "unavailable:%d" % e.code

    return {
        "claim_type": CLAIM_TYPE,
        "issuer": issuer,
        "subject": "hf:model/%s@%s" % (model_id, sha),
        "model": {
            "id": meta.get("id"),
            "sha": sha,
            "created_at": meta.get("createdAt"),
            "last_modified": meta.get("lastModified"),
            "gated": bool(meta.get("gated")),
            "private": bool(meta.get("private")),
            "disabled": bool(meta.get("disabled")),
            "downloads": meta.get("downloads"),
        },
        "card": {
            "sha256": card_sha256,
            "bytes": card_bytes,
            "model_index": bool(meta.get("model-index")),
        },
        "observed": {"via": "huggingface.co API", "path": "/api/models/%s" % model_id},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", action="append", default=[])
    ap.add_argument("--models", help="file with one model id per line")
    ap.add_argument("--out", required=True)
    ap.add_argument("--issuer", default="did:web:markovianprotocol.com")
    a = ap.parse_args()

    ids = list(a.model)
    if a.models:
        with open(a.models) as fh:
            ids += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not ids:
        ap.error("give --model or --models")

    os.makedirs(a.out, exist_ok=True)
    made = failed = 0
    for mid in ids:
        try:
            leaf = attest(mid, a.issuer)
        except Exception as e:
            print("  %-44s FAILED %r" % (mid, e))
            failed += 1
            continue
        name = mid.replace("/", "__")
        with open(os.path.join(a.out, name + ".leaf"), "wb") as fh:
            fh.write(jcs.encode(leaf))
        made += 1
        print("  %-44s %s card=%s%s"
              % (mid, str(leaf["model"]["sha"])[:12],
                 str(leaf["card"]["sha256"])[:12],
                 "  GATED" if leaf["model"]["gated"] else ""))
    print("\n%d leaf/leaves written, %d failed" % (made, failed))
    print("Nothing submitted. Each records what the Hub served just now: the "
          "head commit,")
    print("and a digest of the card at that commit. If the repo is later gated, "
          "pulled, or")
    print("rewritten, this is what it said and when.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
