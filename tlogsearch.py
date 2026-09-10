#!/usr/bin/env python3
"""Search a transparency log export, and bind the answer to a root you re-derive.

Every log search tool in the wild answers from an index the operator built. Ask
crt.sh or search.sigstore.dev for the entries matching X and you get some
entries; nothing in the answer stops the operator from returning fewer than
exist. The absence of a result means nothing at all.

This searches the leaves themselves, recomputes the RFC 6962 root over every one
of them, and checks that root against the signed checkpoint. So a hit carries its
own index, and -- the part that is usually missing -- a miss is a statement:
nothing in the committed tree matches.

Stdlib only, no network. Point it at a terminal export directory.

    python3 tlogsearch.py --export ./export "anchor"
    python3 tlogsearch.py --export ./export --field kind=anchor
    python3 tlogsearch.py --export ./export --regex 'sha256:[0-9a-f]{8}'
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
import ed25519


# ---------------------------------------------------------------- RFC 6962

def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def split_point(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(hashes):
    if not hashes:
        return hashlib.sha256(b"").digest()

    def build(hs):
        if len(hs) == 1:
            return hs[0]
        k = split_point(len(hs))
        return node_hash(build(hs[:k]), build(hs[k:]))

    # Depth is log2(n), but raise the limit anyway so a large export cannot turn
    # into a RecursionError that reads like a verification failure.
    sys.setrecursionlimit(max(10000, len(hashes)))
    return build(hashes)


# ------------------------------------------------------------ the checkpoint

def parse_checkpoint(text):
    body, _, sigtext = text.partition("\n\n")
    lines = body.split("\n")
    origin, size, root_b64 = lines[0], int(lines[1]), lines[2]
    sigs = []
    for line in sigtext.split("\n"):
        if not line.startswith("— "):
            continue
        try:
            name, b64 = line[2:].split(" ", 1)
            sigs.append((name, base64.b64decode(b64)))
        except Exception:
            continue
    return origin, size, root_b64, body + "\n", sigs


def parse_vkey(vkey):
    name, rest = vkey.split("+", 1)
    kid, b64 = rest.split("+", 1)
    blob = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    return name, kid, blob[0], blob[1:]


def verify_checkpoint(export, body, sigs, origin):
    """Log signature, then cosignatures from keys the signed trust root names.

    A cosignature from a key the trust root does not name is reported, never
    counted: that is the whole point of having a signed root.
    """
    results = {"log": False, "witnesses": [], "advisory": [], "quorum": None}

    log_vkey = read_text(export, "log_vkey.txt").strip()
    _, _, _, log_pub = parse_vkey(log_vkey)
    log_kid = parse_vkey(log_vkey)[1]
    for name, raw in sigs:
        if name == origin and len(raw) == 68 and raw[:4].hex() == log_kid:
            if ed25519.checkvalid(raw[4:], body.encode(), log_pub):
                results["log"] = True

    rooted = set()
    try:
        tr = json.loads(read_text(export, "trust-root.json"))
        results["quorum"] = tr.get("witness_quorum")
        for vk in tr.get("witness_vkeys", []):
            rooted.add(parse_vkey(vk)[0])
    except Exception:
        pass

    pinned = {}
    try:
        wk = json.loads(read_text(export, "witness_keys.json"))
        for e in wk.get("keys", []):
            n, kid, _alg, pub = parse_vkey(e["vkey"])
            pinned[(n, kid)] = pub
    except Exception:
        pass

    for name, raw in sigs:
        if len(raw) != 76:            # keyid(4) + timestamp(8) + ed25519(64)
            continue
        pub = pinned.get((name, raw[:4].hex()))
        if pub is None:
            continue
        ts = int.from_bytes(raw[4:12], "big")
        msg = ("cosignature/v1\ntime %d\n%s" % (ts, body)).encode()
        if ed25519.checkvalid(raw[12:], msg, pub):
            (results["witnesses"] if name in rooted else results["advisory"]).append(name)
    return results


# ----------------------------------------------------------------- the search

def read_text(export, name):
    with open(os.path.join(export, name), "r") as fh:
        return fh.read()


def load_leaves(export):
    out = []
    with open(os.path.join(export, "leaves.jsonl"), "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            out.append((rec["index"], base64.b64decode(rec["data_b64"])))
    out.sort(key=lambda t: t[0])
    return out


def matches(data, args):
    if args.regex:
        return re.search(args.regex, data.decode("utf-8", "replace")) is not None
    if args.field:
        key, _, want = args.field.partition("=")
        try:
            obj = json.loads(data)
        except Exception:
            return False
        return str(obj.get(key)) == want
    return args.query.encode() in data


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("query", nargs="?", help="substring to look for in the leaf bytes")
    ap.add_argument("--export", default=".", help="terminal export directory")
    ap.add_argument("--field", help="match a top-level JSON field, as key=value")
    ap.add_argument("--regex", help="match a regex against the decoded leaf")
    ap.add_argument("--limit", type=int, default=20, help="matches to print (0 = all)")
    args = ap.parse_args()
    if not (args.query or args.field or args.regex):
        ap.error("give a query, --field, or --regex")

    export = args.export
    origin, size, root_b64, body, sigs = parse_checkpoint(read_text(export, "checkpoint.txt"))
    leaves = load_leaves(export)

    # 1. Does the bundle hold the whole committed tree?
    if len(leaves) != size:
        print("REFUSING TO SEARCH: bundle holds %d leaves, checkpoint commits %d."
              % (len(leaves), size))
        print("A search over part of a tree cannot tell you anything about absence.")
        return 2
    if [i for i, _ in leaves] != list(range(size)):
        print("REFUSING TO SEARCH: leaf indices are not 0..%d with no gaps." % (size - 1))
        return 2

    # 2. Do those leaves reproduce the committed root?
    computed = base64.b64encode(merkle_root([leaf_hash(d) for _, d in leaves])).decode()
    if computed != root_b64:
        print("REFUSING TO SEARCH: recomputed root does not match the checkpoint.")
        print("  recomputed %s\n  checkpoint %s" % (computed, root_b64))
        return 2

    # 3. Is that checkpoint signed, and cosigned by enough independent witnesses?
    #
    # These are refusals, not warnings. An earlier version of this tool printed
    # the cosignature count and searched anyway, which made it looser than
    # verify_export.py in the same bundle -- two tools, two standards, and the
    # weaker one answering questions about absence.
    v = verify_checkpoint(export, body, sigs, origin)
    if not v["log"]:
        print("REFUSING TO SEARCH: the checkpoint carries no valid log signature.")
        return 2
    if v["quorum"] is None:
        print("REFUSING TO SEARCH: the trust root states no witness quorum, so "
              "there is no threshold to hold this checkpoint to.")
        return 2
    if len(v["witnesses"]) < v["quorum"]:
        print("REFUSING TO SEARCH: %d independent witness cosignature(s), quorum "
              "is %d." % (len(v["witnesses"]), v["quorum"]))
        print("A tree only one party vouches for cannot tell you what is absent "
              "from it.")
        if v["advisory"]:
            print("(%d cosignature(s) verify but are not named by the signed trust "
                  "root, so they do not count: %s)"
                  % (len(v["advisory"]), ", ".join(sorted(v["advisory"]))))
        return 2

    hits = [(i, d) for i, d in leaves if matches(d, args)]
    shown = hits if args.limit == 0 else hits[:args.limit]
    for i, d in shown:
        try:
            text = json.dumps(json.loads(d), sort_keys=True)
        except Exception:
            text = repr(d)
        print("%6d  %s" % (i, text[:160]))
    if len(hits) > len(shown):
        print("... %d more (use --limit 0)" % (len(hits) - len(shown)))

    print()
    print("%d match%s in %d leaves." % (len(hits), "" if len(hits) == 1 else "es", size))
    print("Searched every leaf committed by root %s, recomputed here from the leaves"
          % root_b64[:16] + "...")
    print("themselves. Log signature verifies. %d independent witness "
          "cosignature(s) verify, quorum %d."
          % (len(v["witnesses"]), v["quorum"]))
    if v["advisory"]:
        print("(%d cosignature(s) verify but are not named by the signed trust root, "
              "excluded: %s)" % (len(v["advisory"]), ", ".join(sorted(v["advisory"]))))
    if not hits:
        print("Nothing matched, and that is a claim: no leaf in the committed tree "
              "matches.")
    print()
    print("What this does not tell you: whether any matching leaf is true, and "
          "whether the")
    print("log ever served a different tree to someone else. The first is not a "
          "log's job.")
    print("The second is what the witness cosignatures above are for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
