#!/usr/bin/env python3
"""Reference implementation of reduction/v1 — see spec/reduction-v1.md.

Replays a transparency log export's leaves in index order and produces a table
keyed on (issuer, subject), plus the quad that makes the table checkable:

    (root, tree_size, reduction_sha256, table_sha256)

The point is not the table. Anyone can build a table. The point is that this
function is written down, so a second implementation produces the same
table_sha256 or one of us is wrong — and until now, an index over a log was
whatever the operator's code did that day.

Stdlib only, no network.

    python3 reduce.py --export ./export
    python3 reduce.py --export ./export --lookup did:key:abc --subject foo
    python3 reduce.py --export ./export --table rows.jsonl
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import jcs
import subtree as st
import tlogsearch as ts

SPEC = os.path.join(HERE, "spec", "reduction-v1.md")
NOTE_RE = re.compile(r"^public-note:v1 sha256:([0-9a-f]{64}) (\S+)$")

MALFORMED = object()


# ------------------------------------------------------------------ §2 parse

def _no_duplicate_keys(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError("duplicate object key: %r" % k)
        seen.add(k)
    return dict(pairs)


# §2: the number rule is scoped to what the reduction emits, not to the whole
# leaf. A float in a claim payload -- leaf 339 carries "score": 0.91 -- never
# reaches a row, so rejecting the leaf over it would discard a valid claim to
# guard a canonicalisation hazard that cannot occur. Every field v1 emits is a
# string or an integer this code computes itself.


def parse(data):
    """-> ('json', obj) | ('note', {...}) | MALFORMED"""
    try:
        text = data.decode("utf-8")          # strict: no replacement characters
    except UnicodeDecodeError:
        return MALFORMED
    m = NOTE_RE.match(text.strip())
    if m:
        return ("note", {"sha256": m.group(1), "timestamp": m.group(2)})
    try:
        o = json.loads(text, object_pairs_hook=_no_duplicate_keys,
                       parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except Exception:
        return MALFORMED
    if not isinstance(o, dict):
        return MALFORMED
    return ("json", o)


# ------------------------------------------------- §3 type, §4 issuer, §5 subject

def _core(o):
    c = o.get("core")
    return c if isinstance(c, dict) else {}


def typeof(o):
    for path in (("claim_type",), ("claimType",), ("core", "claimType"), ("kind",)):
        v = o
        for p in path:
            v = v.get(p) if isinstance(v, dict) else None
        if isinstance(v, str):
            return v
    return None


def issuer_of(o):
    if isinstance(o.get("issuer"), str):
        return o["issuer"]
    c = _core(o).get("issuer")
    return c if isinstance(c, str) else None


def subject_of(o):
    s = o.get("subject")
    if isinstance(s, str):
        return s
    if isinstance(s, dict) and isinstance(s.get("name"), str):
        return s["name"]
    cs = _core(o).get("subject")
    if isinstance(cs, dict) and isinstance(cs.get("name"), str):
        return cs["name"]
    return None          # a subject object without a name is NO_KEY (§5)


ROTATION_TYPE = "https://markovianprotocol.com/claim/key-rotation/v1"
RETRACTION_TYPES = ()    # §8: none exist in this log yet
EXCLUDED_TYPES = ("reduction-manifest/v1",)   # §13: never in its own key space


# ---------------------------------------------------------------- the reduction

def reduce_leaves(leaves):
    rows = {}
    malformed = []
    skipped = {}
    rotations = []

    def skip(reason):
        skipped[reason] = skipped.get(reason, 0) + 1

    for index, data in leaves:
        p = parse(data)
        if p is MALFORMED:
            malformed.append(index)
            continue
        kind, o = p
        if kind == "note":
            skip("plaintext-note")
            continue

        ctype = typeof(o)
        if ctype is None:
            skip("untyped")
            continue
        if ctype in EXCLUDED_TYPES:
            skip("excluded-type")
            continue
        if ctype == ROTATION_TYPE:
            claim = _core(o).get("claim") if _core(o) else o.get("claim")
            if isinstance(claim, dict) and isinstance(claim.get("old_did"), str) \
                    and isinstance(claim.get("new_did"), str):
                rotations.append({"index": index, "old": claim["old_did"],
                                  "new": claim["new_did"]})
            # a rotation leaf is still a claim about its own subject; fall through

        iss = issuer_of(o)
        sub = subject_of(o)
        if iss is None or sub is None:
            skip("no-issuer" if iss is None else "no-subject")
            continue

        key = (iss, sub)
        leaf_hash = hashlib.sha256(data).hexdigest()
        row = rows.get(key)
        if row is None:
            rows[key] = {"issuer": iss, "subject": sub, "claim_type": ctype,
                         "first_index": index, "last_index": index,
                         "superseded_count": 0, "leaf_sha256": leaf_hash,
                         "state": "active"}
        else:
            # §7 last write by index wins; the log hands leaves to us in order
            row["superseded_count"] += 1
            row["last_index"] = index
            row["claim_type"] = ctype
            row["leaf_sha256"] = leaf_hash

    return rows, malformed, skipped, rotations


def inclusion_proof(hashes, index):
    """RFC 6962 audit path for `index` within the tree over `hashes`."""
    def walk(lo, hi):
        if hi - lo == 1:
            return []
        k = st._split(hi - lo)
        if index < lo + k:
            return walk(lo, lo + k) + [st.mth(hashes[lo + k:hi])]
        return walk(lo + k, hi) + [st.mth(hashes[lo:lo + k])]
    return walk(0, len(hashes))


def serialize(rows):
    """§11: byte-wise sort on the key, one JCS object per line, LF, trailing LF."""
    out = []
    for key in sorted(rows, key=lambda k: (k[0].encode(), k[1].encode())):
        out.append(jcs.encode(rows[key]))
    blob = b"\n".join(out) + (b"\n" if out else b"")
    return blob, hashlib.sha256(blob).hexdigest()


def spec_digest():
    with open(SPEC, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# ------------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export", default=".")
    ap.add_argument("--lookup", help="issuer to look up")
    ap.add_argument("--subject", help="subject to look up; with --lookup, one row")
    ap.add_argument("--table", help="write the canonical table to this path")
    ap.add_argument("--as-of", type=int, metavar="N",
                    help="reduce the tree as it stood at size N, and prove that "
                         "state consistent with the signed head")
    ap.add_argument("--receipt", nargs=2, metavar=("ISSUER", "SUBJECT"),
                    help="emit a portable receipt for one row: the row, its leaf, "
                         "an inclusion proof, and the cosigned checkpoint")
    a = ap.parse_args()

    export = a.export
    checkpoint_text = ts.read_text(export, "checkpoint.txt")
    origin, size, root_b64, body, sigs = ts.parse_checkpoint(checkpoint_text)
    leaves = ts.load_leaves(export)

    # §12.1-3, the same refusals tlogsearch makes
    if len(leaves) != size:
        print("REFUSING TO REDUCE: bundle holds %d leaves, checkpoint commits %d."
              % (len(leaves), size))
        return 2
    if [i for i, _ in leaves] != list(range(size)):
        print("REFUSING TO REDUCE: leaf indices are not 0..%d with no gaps." % (size - 1))
        return 2
    computed = base64.b64encode(
        ts.merkle_root([ts.leaf_hash(d) for _, d in leaves])).decode()
    if computed != root_b64:
        print("REFUSING TO REDUCE: recomputed root does not match the checkpoint.")
        print("  recomputed %s\n  checkpoint %s" % (computed, root_b64))
        return 2

    # §12.4
    v = ts.verify_checkpoint(export, body, sigs, origin)
    if not v["log"]:
        print("REFUSING TO REDUCE: the checkpoint carries no valid log signature.")
        return 2
    if v["quorum"] is None:
        print("REFUSING TO REDUCE: the trust root states no witness quorum.")
        return 2
    if len(v["witnesses"]) < v["quorum"]:
        print("REFUSING TO REDUCE: %d independent witness cosignature(s), quorum %d."
              % (len(v["witnesses"]), v["quorum"]))
        return 2

    as_of = a.as_of if a.as_of is not None else size
    if as_of > size:
        print("REFUSING: asked for size %d, the signed checkpoint commits %d."
              % (as_of, size))
        return 2
    hashes = [ts.leaf_hash(d) for _, d in leaves]
    consistency = None
    if as_of != size:
        # An older tree state is only meaningful if it is provably the same log.
        # SUBTREE_PROOF(0, m, D_n) is the RFC 6962 consistency proof, and this
        # is the implementation cross-checked against torchwood.
        root_asof = st.mth(hashes[:as_of])
        consistency = st.subtree_proof(0, as_of, hashes)
        if not st.verify_subtree_proof(0, as_of, size, consistency, root_asof,
                                       base64.b64decode(root_b64)):
            print("REFUSING: could not prove size %d consistent with the signed "
                  "head at %d." % (as_of, size))
            return 2
        print("as of tree size %d, root %s"
              % (as_of, base64.b64encode(root_asof).decode()))
        print("  proven consistent with the signed head at %d, %d hashes"
              % (size, len(consistency)))

    rows, malformed, skipped, rotations = reduce_leaves(leaves[:as_of])
    blob, table_sha = serialize(rows)
    reduction_sha = spec_digest()

    if a.table:
        with open(a.table, "wb") as fh:
            fh.write(blob)
        print("wrote %s (%d rows)" % (a.table, len(rows)))
        # §9.4: the identity graph ships beside the table, so a rotation chain
        # stays inspectable instead of folded into the rows. Issuers in the
        # table are literal bytes (§4); nothing here rewrites them.
        gpath = os.path.splitext(a.table)[0] + ".identity.json"
        with open(gpath, "wb") as fh:
            fh.write(jcs.encode({"rotations": rotations,
                                 "applies": "forward only, to indices above each "
                                            "rotation's own index"}) + b"\n")
        print("wrote %s (%d rotation(s))" % (gpath, len(rotations)))

    if a.receipt:
        iss, sub = a.receipt
        row = rows.get((iss, sub))
        if row is None:
            print("no row for that (issuer, subject) at size %d." % as_of)
            print("This is a miss, not an absence claim: %d leaves were malformed "
                  "or skipped." % (len(malformed) + sum(skipped.values()))
                  if (malformed or skipped) else "")
            return 2
        idx = row["last_index"]
        leaf = dict(leaves)[idx]
        proof = inclusion_proof(hashes[:as_of], idx)
        receipt = {
            "receipt": "markovian-reduction-receipt/v1",
            "origin": origin,
            "tree_size": as_of,
            "root": base64.b64encode(st.mth(hashes[:as_of])).decode(),
            "reduction_sha256": reduction_sha,
            "row": row,
            "leaf_index": idx,
            "leaf_b64": base64.b64encode(leaf).decode(),
            "inclusion_proof": [base64.b64encode(h).decode() for h in proof],
            "checkpoint": checkpoint_text,
            "consistency_to_head": (
                [base64.b64encode(h).decode() for h in consistency]
                if consistency else None),
            "how_to_check": (
                "sha256(0x00||leaf_b64) with inclusion_proof recomputes root; "
                "the row's fields are what reduction_sha256 says to derive from "
                "that leaf; checkpoint carries the log signature and witness "
                "cosignatures over root. Nothing here needs the operator."),
        }
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0

    if a.lookup:
        hits = [r for k, r in rows.items() if k[0] == a.lookup
                and (a.subject is None or k[1] == a.subject)]
        for r in sorted(hits, key=lambda r: r["subject"]):
            print(jcs.dumps(r))
        print("\n%d row(s)." % len(hits))
    elif a.subject:
        # §12.7: a subject alone is not a key. Return every issuer's row.
        hits = [r for k, r in rows.items() if k[1] == a.subject]
        for r in sorted(hits, key=lambda r: r["issuer"]):
            print(jcs.dumps(r))
        if len(hits) > 1:
            print("\n%d issuers claim this subject. This is not a tie to be broken;"
                  % len(hits))
            print("the log holds %d disagreeing claims about it." % len(hits))
        else:
            print("\n%d row(s)." % len(hits))

    print()
    print("rows            %d" % len(rows))
    print("malformed       %d" % len(malformed))
    print("skipped         %s" % (json.dumps(skipped, sort_keys=True) if skipped else "{}"))
    print("rotations seen  %d" % len(rotations))
    print()
    # The quad must describe the tree that was actually answered, not the head.
    answered_root = (base64.b64encode(st.mth(hashes[:as_of])).decode()
                     if as_of != size else root_b64)
    print("root            %s" % answered_root)
    print("tree_size       %d" % as_of)
    if as_of != size:
        print("                (signed head is %d; consistency proven above)" % size)
    print("reduction_sha256 %s" % reduction_sha)
    print("table_sha256    %s" % table_sha)
    print("witnesses       %d (quorum %d)" % (len(v["witnesses"]), v["quorum"]))

    if malformed or skipped:
        print()
        print("This result cannot answer a question about absence: %d leaves were"
              % (len(malformed) + sum(skipped.values())))
        print("malformed or skipped, and any one of them might have been the row")
        print("you asked for. Hits above are still hits; a miss is not a miss.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
