#!/usr/bin/env python3
"""Verify a transparency log export's Bitcoin anchors offline.

The export ships OpenTimestamps proofs next to its anchored checkpoints, and
until now nothing checked them: the standard client needs a network, so the
bundle could only report that an .ots file was present.

The missing input is small. A Bitcoin header is 80 bytes, and the proofs here
span a few thousand blocks, so the headers ship alongside them. Then the whole
check is arithmetic:

  1. every header hashes to the next one's prev-block field, so the run is a chain
  2. every header meets its own stated difficulty, so the chain cost work
  3. every OTS proof replays from the file's digest to a merkle root, and that
     root is the one in the header at the height the attestation names

Stdlib only, no network.

    python3 verify_anchors.py --export ./export --headers headers.bin

What it does not establish: that this chain is Bitcoin's main chain. That needs
either more chain than an export should carry, or one hash you already trust --
pass --expect-hash HEIGHT:HASH with a block hash you know from anywhere else and
the run will check it.
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ots


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def bits_to_target(bits):
    exponent = bits >> 24
    mantissa = bits & 0xffffff
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


class Headers:
    def __init__(self, path, meta_path):
        with open(path, "rb") as fh:
            self.raw = fh.read()
        if len(self.raw) % 80:
            raise SystemExit("%s is not a whole number of 80-byte headers" % path)
        with open(meta_path) as fh:
            meta = json.load(fh)
        self.start = meta["start_height"]
        self.count = len(self.raw) // 80
        if meta.get("count") not in (None, self.count):
            raise SystemExit("headers.json count %s disagrees with the file's %d"
                             % (meta.get("count"), self.count))

    def at(self, height):
        i = height - self.start
        if i < 0 or i >= self.count:
            return None
        return self.raw[i * 80:(i + 1) * 80]

    def merkle_root(self, height):
        h = self.at(height)
        return None if h is None else h[36:68]

    def check_chain(self):
        """Linkage and proof of work, for the whole run."""
        broken, weak = [], []
        prev = None
        for i in range(self.count):
            h = self.raw[i * 80:(i + 1) * 80]
            if prev is not None and h[4:36] != sha256d(prev):
                broken.append(self.start + i)
            target = bits_to_target(int.from_bytes(h[72:76], "little"))
            if int.from_bytes(sha256d(h)[::-1], "big") > target:
                weak.append(self.start + i)
            prev = h
        return broken, weak


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export", default=".")
    ap.add_argument("--headers", default="headers.bin")
    ap.add_argument("--expect-hash", action="append", default=[],
                    metavar="HEIGHT:HASH",
                    help="a block hash you already trust, checked against the run")
    ap.add_argument("--limit-failures", type=int, default=10)
    a = ap.parse_args()

    hdr = Headers(a.headers, os.path.splitext(a.headers)[0] + ".json")
    print("headers: %d, heights %d..%d"
          % (hdr.count, hdr.start, hdr.start + hdr.count - 1))

    broken, weak = hdr.check_chain()
    print("chain linkage: %s" % ("PASS" if not broken else
                                 "FAIL at %s" % broken[:5]))
    print("proof of work: %s" % ("PASS, every header meets its stated target"
                                 if not weak else "FAIL at %s" % weak[:5]))

    for spec in a.expect_hash:
        height, want = spec.split(":", 1)
        got = sha256d(hdr.at(int(height)))[::-1].hex()
        print("anchor hash at %s: %s" % (height, "PASS" if got == want.lower()
                                         else "FAIL got %s" % got))

    andir = os.path.join(a.export, "anchors")
    files = sorted(f for f in os.listdir(andir) if f.endswith(".ots"))
    verified = pending = missing = 0
    failures = []
    for f in files:
        base = os.path.join(andir, f[:-4])
        proof = open(os.path.join(andir, f), "rb").read()
        try:
            digest, ats = ots.bitcoin_attestations(proof)
        except ots.OTSError as e:
            failures.append((f, "unparseable: %s" % e))
            continue
        actual = hashlib.sha256(open(base, "rb").read()).digest()
        if actual != digest:
            failures.append((f, "proof is for a different file"))
            continue
        if not ats:
            pending += 1
            continue
        hit = False
        for at in ats:
            root = hdr.merkle_root(at["height"])
            if root is None:
                missing += 1
                continue
            if root == at["message"]:
                hit = True
            else:
                failures.append((f, "height %d merkle root mismatch" % at["height"]))
        if hit:
            verified += 1

    print()
    print("anchors: %d of %d proofs replay to a merkle root in these headers."
          % (verified, len(files)))
    if pending:
        print("  %d carry no Bitcoin attestation yet (calendar pending)." % pending)
    if missing:
        print("  %d name a height outside the shipped range." % missing)
    for f, why in failures[:a.limit_failures]:
        print("  FAIL %s: %s" % (f, why))
    if len(failures) > a.limit_failures:
        print("  ... %d more failures" % (len(failures) - a.limit_failures))

    print()
    print("Each anchor above is a checkpoint of this log whose digest was hashed "
          "into a")
    print("Bitcoin block: the log could not have produced that root later than "
          "the block.")
    print("It says nothing about whether the log served the same tree to "
          "everyone, and")
    print("these headers are a chain that cost work, not a proof that it is the "
          "chain.")
    return 1 if (broken or weak or failures) else 0


if __name__ == "__main__":
    sys.exit(main())
