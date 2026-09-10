#!/usr/bin/env python3
"""Collect a contiguous run of Bitcoin block headers, so the export can check its
own anchors offline.

This is the only part that touches the network, and it runs at build time, never
at verification time.

It fetches block metadata ten at a time and rebuilds each 80-byte header from
it, then checks that the rebuilt header hashes to the block id the server stated
for it. So the reconstruction is self-checking: a server that lies about any
header field produces bytes that do not hash to the id it also served. Linkage
and proof of work are re-checked separately by verify_anchors.py, which trusts
neither this script nor its source.

    python3 fetch_headers.py --from 957788 --to 966218 --out headers.bin

Writes headers.bin (80 bytes per block, ascending) and headers.json (the start
height and the count).

It is deliberately slow. Blockstream caps unauthenticated use at 700 requests
per hour per IP, which is why one request per block does not work at all: 8431
blocks is twelve hours and a wall of 429s. Ten blocks per request turns that
into 844 calls, paced just under the cap. Progress is written to disk as it
goes, so a throttled or interrupted run resumes from what it already has.
"""
import argparse
import hashlib
import json
import os
import sys
import struct
import time
import urllib.error
import urllib.request

API = "https://blockstream.info/api"


BATCH = 10            # blocks per /blocks/<height> call
DELAY = 5.2           # 700 requests/hour is the documented unauthenticated cap
_last = [0.0]


def get(path, retries=6):
    for attempt in range(retries):
        gap = DELAY - (time.time() - _last[0])
        if gap > 0:
            time.sleep(gap)
        try:
            with urllib.request.urlopen(API + path, timeout=30) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code != 429:
                raise
            # Rate limited: back off hard, and for longer each time. This is the
            # failure that actually happens on a few-thousand-block run.
            wait = min(60.0, 5.0 * (2 ** attempt))
            print("  429, waiting %.0fs" % wait, flush=True)
            time.sleep(wait)
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(1.5 * (attempt + 1))
        finally:
            _last[0] = time.time()
    raise SystemExit("gave up after %d attempts on %s" % (retries, path))


def block_hash(header):
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()


def build_header(b):
    """The 80 bytes, rebuilt from the metadata the API returns."""
    return (struct.pack("<i", b["version"])
            + bytes.fromhex(b["previousblockhash"])[::-1]
            + bytes.fromhex(b["merkle_root"])[::-1]
            + struct.pack("<I", b["timestamp"])
            + struct.pack("<I", b["bits"])
            + struct.pack("<I", b["nonce"]))


def headers_from(height):
    """Ten headers, descending from `height`, each checked against its own id."""
    blocks = json.loads(get("/blocks/%d" % height).decode())
    out = {}
    for b in blocks:
        h = build_header(b)
        if block_hash(h)[::-1].hex() != b["id"]:
            raise SystemExit("rebuilt header for %d does not hash to the id served "
                             "for it -- refusing to write it" % b["height"])
        out[b["height"]] = h
    return out


def prev_hash(header):
    return header[4:36]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="lo", type=int, required=True)
    ap.add_argument("--to", dest="hi", type=int, required=True)
    ap.add_argument("--out", default="headers.bin")
    a = ap.parse_args()
    if a.hi < a.lo:
        raise SystemExit("--to must be >= --from")

    n = a.hi - a.lo + 1
    progress_path = a.out + ".progress.json"
    have = {}
    if os.path.exists(progress_path):
        with open(progress_path) as fh:
            saved = json.load(fh)
        if saved.get("hi") == a.hi:
            have = {int(k): bytes.fromhex(v) for k, v in saved["headers"].items()}
            print("resuming: %d of %d already fetched" % (len(have), n))

    def flush():
        tmp = progress_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"hi": a.hi,
                       "headers": {str(k): v.hex() for k, v in have.items()}}, fh)
        os.replace(tmp, progress_path)

    # Walk downwards in batches, skipping any run already held.
    height = a.hi
    try:
        while height >= a.lo:
            if height in have:
                height -= 1
                continue
            got = headers_from(height)
            for hh, raw in got.items():
                if a.lo <= hh <= a.hi:
                    have[hh] = raw
            height = min(got) - 1 if got else height - 1
            flush()
            print("  %d/%d" % (len(have), n), flush=True)
    finally:
        flush()

    missing = [h for h in range(a.lo, a.hi + 1) if h not in have]
    if missing:
        print("incomplete: %d headers still missing (%d..%d). Re-run the same "
              "command to resume." % (len(missing), missing[0], missing[-1]))
        return 1

    with open(a.out, "wb") as fh:
        fh.write(b"".join(have[h] for h in range(a.lo, a.hi + 1)))
    os.remove(progress_path)
    meta = {"start_height": a.lo, "count": n,
            "source": API,
            "note": ("80-byte Bitcoin block headers, ascending from start_height, "
                     "no gaps. Fetched once at build time; verification is offline "
                     "and re-checks the prev-block linkage and the proof of work "
                     "rather than trusting this file's provenance.")}
    with open(os.path.splitext(a.out)[0] + ".json", "w") as fh:
        json.dump(meta, fh, indent=2)
        fh.write("\n")
    print("wrote %s (%d bytes) and its .json" % (a.out, n * 80))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
