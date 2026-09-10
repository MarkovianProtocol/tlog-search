#!/usr/bin/env python3
"""Collect a contiguous run of Bitcoin block headers, so the export can check its
own anchors offline.

This is the only part that touches the network, and it runs at build time, never
at verification time. It walks backwards from a known block using each header's
own prev-block field, so the sequence it writes is linked by construction and a
verifier can re-check that linkage without trusting this script.

    python3 fetch_headers.py --from 957788 --to 966218 --out headers.bin

Writes headers.bin (80 bytes per block, ascending) and headers.json (the start
height and the count).

It is deliberately slow. Public block explorers rate-limit, and a few thousand
headers fetched flat out earns an HTTP 429 partway through and leaves nothing
behind. So requests are paced, 429 is backed off separately from other errors,
and progress is written to disk as it goes: re-running with the same --out
resumes from what is already there instead of starting again.
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://blockstream.info/api"


DELAY = 0.25          # between requests, so a long run does not look like a flood
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


def hash_at(height):
    return get("/block-height/%d" % height).decode().strip()


def header_of(block_hash):
    raw = bytes.fromhex(get("/block/%s/header" % block_hash).decode().strip())
    if len(raw) != 80:
        raise SystemExit("header for %s is %d bytes, expected 80" % (block_hash, len(raw)))
    return raw


def block_hash(header):
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()


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

    # Walk backwards from the top so each header's prev field names the next one
    # we ask for. One height lookup for the anchor, then one call per block.
    height = a.hi
    while height in have:
        height -= 1
    cur = (prev_hash(have[height + 1])[::-1].hex() if height + 1 in have
           else hash_at(a.hi))

    try:
        while height >= a.lo:
            h = header_of(cur)
            have[height] = h
            cur = prev_hash(h)[::-1].hex()
            height -= 1
            done = len(have)
            if done % 250 == 0:
                flush()
                print("  %d/%d" % (done, n), flush=True)
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
