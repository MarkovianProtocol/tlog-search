#!/usr/bin/env python3
"""A c2sp.org/tlog-mirror client: feed a log to a mirror.

A witness says it saw a root. A mirror says it holds the bytes and will serve
them. Getting a log mirrored means pushing it: the mirror exposes add-checkpoint
and add-entries, and a client like this one reads the log and uploads it.

    python3 mirror_client.py --export ./export --dry-run --out ./requests
    python3 mirror_client.py --export ./export --submission https://mirror.example/m

Entries go up in packages aligned to multiples of 256, each carrying a subtree
consistency proof so the mirror can verify and commit a package without
buffering the whole upload. Those proofs are computed by subtree.py, which
agrees byte for byte with filippo.io/torchwood on this log's real tree.

Honest scope: the proof and framing code is exercised against a real log and
cross-checked against an independent implementation. The HTTP path has never
been run against a live mirror, because none was reachable to test with. Treat
--dry-run output as the checked artifact and the network path as unproven.
"""
import argparse
import base64
import hashlib
import os
import struct
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import subtree as st
import tlogsearch as ts

PACKAGE = 256


def build_packages(leaves, upload_start, upload_end, hashes):
    """The canonical sequence of entry packages for [upload_start, upload_end).

    Note the proof is over the subtree that begins at the 256-aligned boundary,
    not at upload_start: a package that starts mid-block still proves the whole
    aligned subtree it belongs to.
    """
    if upload_start == upload_end:
        return []
    rounded_start = (upload_start // PACKAGE) * PACKAGE
    rounded_end = -(-upload_end // PACKAGE) * PACKAGE
    out = []
    for i in range((rounded_end - rounded_start) // PACKAGE):
        start = max(upload_start, rounded_start + i * PACKAGE)
        end = min(upload_end, rounded_start + (i + 1) * PACKAGE)
        if start >= end:
            continue
        sub_start = rounded_start + i * PACKAGE
        proof = st.subtree_proof(sub_start, end, hashes[:upload_end])
        if len(proof) > 63:
            raise SystemExit("proof for [%d, %d) has %d hashes, over the 63 the "
                             "wire format allows" % (sub_start, end, len(proof)))
        body = b"".join(struct.pack(">H", len(d)) + d
                        for _, d in leaves[start:end])
        body += struct.pack(">B", len(proof)) + b"".join(proof)
        out.append({"start": start, "end": end, "subtree_start": sub_start,
                    "proof": proof, "body": body})
    return out


def add_entries_body(origin, upload_start, upload_end, ticket, packages):
    o = origin.encode()
    head = (struct.pack(">H", len(o)) + o
            + struct.pack(">Q", upload_start)
            + struct.pack(">Q", upload_end)
            + struct.pack(">H", len(ticket)) + ticket)
    return head + b"".join(p["body"] for p in packages)


def post(url, body, content_type="application/octet-stream"):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": content_type})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.read()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export", default=".", help="terminal export directory")
    ap.add_argument("--submission", help="mirror submission prefix")
    ap.add_argument("--dry-run", action="store_true",
                    help="build and self-check the requests, send nothing")
    ap.add_argument("--out", help="with --dry-run, write request bodies here")
    ap.add_argument("--from", dest="lo", type=int, default=0)
    ap.add_argument("--max-packages", type=int, default=8,
                    help="packages per add-entries request")
    a = ap.parse_args()
    if not a.submission and not a.dry_run:
        ap.error("give --submission, or --dry-run")

    checkpoint = ts.read_text(a.export, "checkpoint.txt")
    origin, size, root_b64, body, sigs = ts.parse_checkpoint(checkpoint)
    leaves = ts.load_leaves(a.export)
    if len(leaves) != size:
        print("REFUSING: bundle holds %d leaves, checkpoint commits %d."
              % (len(leaves), size))
        return 2
    hashes = [st.leaf_hash(d) for _, d in leaves]
    root = base64.b64decode(root_b64)
    if st.mth(hashes) != root:
        print("REFUSING: leaves do not reproduce the checkpoint root.")
        return 2
    print("%s at size %d, root verified from the leaves" % (origin, size))

    packages = build_packages(leaves, a.lo, size, hashes)
    print("upload [%d, %d) is %d package(s)" % (a.lo, size, len(packages)))

    # Every proof we are about to send is checked before it leaves here. A
    # mirror that trusts a bad package is the mirror's bug; sending one is ours.
    bad = 0
    for p in packages:
        sh = st.mth(hashes[p["subtree_start"]:p["end"]])
        if not st.verify_subtree_proof(p["subtree_start"], p["end"], size,
                                       p["proof"], sh, root):
            bad += 1
            print("  FAIL  package [%d, %d) proof does not verify"
                  % (p["subtree_start"], p["end"]))
    if bad:
        print("REFUSING: %d package(s) carry a proof that does not verify." % bad)
        return 2
    print("all %d package proof(s) verify against the checkpoint root" % len(packages))

    if a.dry_run:
        total = 0
        if a.out:
            os.makedirs(a.out, exist_ok=True)
            with open(os.path.join(a.out, "add-checkpoint.txt"), "w") as fh:
                fh.write(checkpoint)
        for i in range(0, len(packages), a.max_packages):
            chunk = packages[i:i + a.max_packages]
            blob = add_entries_body(origin, chunk[0]["start"], size, b"", chunk)
            total += len(blob)
            if a.out:
                with open(os.path.join(a.out, "add-entries-%04d.bin"
                                       % (i // a.max_packages)), "wb") as fh:
                    fh.write(blob)
        print("built %d add-entries request(s), %d bytes total%s"
              % (-(-len(packages) // a.max_packages), total,
                 " -> %s" % a.out if a.out else ""))
        print("\nNothing was sent. The wire path has never been run against a "
              "live mirror.")
        return 0

    base = a.submission.rstrip("/")
    st_code, _ = post(base + "/add-checkpoint", checkpoint.encode(), "text/plain")
    print("add-checkpoint -> HTTP %d" % st_code)
    for i in range(0, len(packages), a.max_packages):
        chunk = packages[i:i + a.max_packages]
        blob = add_entries_body(origin, chunk[0]["start"], size, b"", chunk)
        code, _ = post(base + "/add-entries", blob)
        print("add-entries [%d, %d) -> HTTP %d"
              % (chunk[0]["start"], chunk[-1]["end"], code))
    return 0


if __name__ == "__main__":
    sys.exit(main())
