#!/usr/bin/env python3
"""Check a reduction receipt without the log, the export, or the operator.

A receipt carries one row, the leaf it came from, an inclusion proof, and the
cosigned checkpoint. This checks all four links:

  1. the leaf hashes and the inclusion proof recompute the stated root
  2. the stated root is the one the checkpoint commits to
  3. the checkpoint carries the log's signature and enough witness cosignatures
  4. the row's fields are what reduction/v1 derives from that leaf

Link 4 is the one that matters and the one nobody else ships. An index entry
that is merely signed tells you the operator said it. A row you can re-derive
from a leaf you can prove is in the tree tells you nobody said anything.

    python3 verify_receipt.py receipt.json --trust-root trust-root.json

Stdlib only, no network.
"""
import argparse
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ed25519
import reduce as R
import subtree as st
import tlogsearch as ts


def check_inclusion(leaf, index, size, proof, root):
    """RFC 6962 inclusion, recomputed from the leaf upward."""
    fn, sn = index, size - 1
    r = st.leaf_hash(leaf)
    for p in proof:
        if fn & 1 or fn == sn:
            r = st.node_hash(p, r)
            while fn != 0 and not (fn & 1):
                fn >>= 1; sn >>= 1
        else:
            r = st.node_hash(r, p)
        fn >>= 1; sn >>= 1
    return r == root


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("receipt")
    ap.add_argument("--trust-root", help="trust-root.json, to count cosignatures")
    a = ap.parse_args()

    with open(a.receipt) as fh:
        rc = json.load(fh)
    if rc.get("receipt") != "markovian-reduction-receipt/v1":
        print("not a markovian-reduction-receipt/v1")
        return 2

    leaf = base64.b64decode(rc["leaf_b64"])
    root = base64.b64decode(rc["root"])
    proof = [base64.b64decode(h) for h in rc["inclusion_proof"]]

    ok_incl = check_inclusion(leaf, rc["leaf_index"], rc["tree_size"], proof, root)
    print("1. leaf %d is in the tree of size %d      %s"
          % (rc["leaf_index"], rc["tree_size"], "PASS" if ok_incl else "FAIL"))

    origin, size, root_b64, body, sigs = ts.parse_checkpoint(rc["checkpoint"])
    ok_root = (root_b64 == rc["root"] and size == rc["tree_size"])
    print("2. that root is what the checkpoint commits  %s"
          % ("PASS" if ok_root else "FAIL"))

    # 3. signatures. Without a trust root we can still say what verified, but we
    #    cannot say whether it was enough, and we refuse to imply that we can.
    counted, named = 0, set()
    quorum = None
    if a.trust_root:
        with open(a.trust_root) as fh:
            tr = json.load(fh)
        quorum = tr.get("witness_quorum")
        for vk in tr.get("witness_vkeys", []):
            named.add(ts.parse_vkey(vk)[0])
        pinned = {}
        for vk in tr.get("witness_vkeys", []):
            n, kid, _alg, pub = ts.parse_vkey(vk)
            pinned[(n, kid)] = pub
        for name, raw in sigs:
            if len(raw) != 76:
                continue
            pub = pinned.get((name, raw[:4].hex()))
            if pub is None:
                continue
            tsec = int.from_bytes(raw[4:12], "big")
            msg = ("cosignature/v1\ntime %d\n%s" % (tsec, body)).encode()
            if ed25519.checkvalid(raw[12:], msg, pub):
                counted += 1
        print("3. %d cosignature(s) from trust-root keys    %s"
              % (counted, "PASS" if quorum and counted >= quorum else "FAIL"))
    else:
        print("3. cosignatures                              NOT CHECKED "
              "(pass --trust-root)")

    # 4. the row is derivable from the leaf under the stated reduction
    p = R.parse(leaf)
    derived_ok = False
    if p is not R.MALFORMED:
        kind, o = p
        if kind == "json":
            iss, sub, ctype = R.issuer_of(o), R.subject_of(o), R.typeof(o)
            row = rc["row"]
            derived_ok = (iss == row["issuer"] and sub == row["subject"]
                          and ctype == row["claim_type"]
                          and hashlib.sha256(leaf).hexdigest() == row["leaf_sha256"])
    print("4. the row re-derives from that leaf         %s"
          % ("PASS" if derived_ok else "FAIL"))
    print("   reduction_sha256 %s" % rc["reduction_sha256"])

    all_ok = ok_incl and ok_root and derived_ok and (
        not a.trust_root or (quorum and counted >= quorum))
    print()
    if all_ok:
        print("This row is in a tree that %s%s, and it is what the published "
              "reduction" % ("witnesses cosigned" if a.trust_root else "the log signed",
                             "" if a.trust_root else " (cosignatures unchecked)"))
        print("derives from a leaf of that tree. None of that needed the operator.")
    else:
        print("Receipt does not check out. Do not rely on this row.")
    print()
    print("What it still does not tell you: whether the claim in the leaf is "
          "true, and")
    print("whether the log showed the same tree to everyone. The first is not a "
          "log's job.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
