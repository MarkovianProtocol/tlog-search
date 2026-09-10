# tlogsearch

Search a transparency log, and get an answer bound to a root you re-derive.

```
python3 tlogsearch.py --export ./export --field kind=anchor
```

```
     1  {"kind": "anchor", "n": 2}
     2  {"kind": "anchor", "n": 3}

2 matches in 7898 leaves.
Searched every leaf committed by root w4EgQfjRRVBy+JSS..., recomputed here from the leaves
themselves. Log signature verifies. 7 independent witness cosignature(s) verify, quorum 4.
(1 cosignature(s) verify but are not named by the signed trust root, excluded: gblin.digital/witness)
```

## Why

Every log search service answers from an index its operator built. Ask crt.sh or
search.sigstore.dev for the entries matching X and you get some entries. Nothing
in the answer stops the operator returning fewer than exist, and a result of zero
tells you nothing whatsoever.

This reads the leaves, recomputes the RFC 6962 root over every one of them, and
checks that root against the signed checkpoint before it will search. So a miss
is a claim: nothing in the committed tree matches.

It refuses rather than degrades. A bundle holding fewer leaves than the
checkpoint commits, a gap in the indices, or leaves that do not reproduce the
root all stop the search:

```
REFUSING TO SEARCH: bundle holds 7897 leaves, checkpoint commits 7898.
A search over part of a tree cannot tell you anything about absence.
```

```
REFUSING TO SEARCH: recomputed root does not match the checkpoint.
  recomputed AWwc9go0MaabLXWTdCCQ3bPjt1P+9pXxjuKVuT/6g+o=
  checkpoint w4EgQfjRRVBy+JSSs8o4H2M0IEMJHeJ0msSDjHhu7Bg=
```

Exit is 0 on a verified search, 1 if the log signature is missing, 2 on a refusal.

## Use

Stdlib only, no network, no install. Ed25519 is implemented in `ed25519.py`
(RFC 8032, checked against test vector 1). Point it at a terminal export
directory — one that carries `leaves.jsonl`, `checkpoint.txt`, `log_vkey.txt`,
`witness_keys.json` and `trust-root.json`.

```
python3 tlogsearch.py --export ./export "anchor"          # substring in the leaf bytes
python3 tlogsearch.py --export ./export --field kind=anchor
python3 tlogsearch.py --export ./export --regex 'sha256:[0-9a-f]{8}'
python3 tlogsearch.py --export ./export --field kind=anchor --limit 0
```

A working export: <https://github.com/MarkovianProtocol/log-terminal-export>.
7898 leaves search in about 0.1s, root recomputation included, so there is no
index to build and nothing to keep in sync.

## What it does not tell you

Whether a matching leaf is true. A log records what was said, not whether it was
so, and no amount of hashing changes that.

Whether the log served a different tree to someone else. That is what the
witness cosignatures in the footer are for, and it is why cosignatures from keys
the signed trust root does not name are reported separately and never counted —
a key vouching for itself is not a second opinion.

---

# Verifying the Bitcoin anchors offline

A transparency log export can ship OpenTimestamps proofs next to its checkpoints
and still not check them. The standard client needs a network, so a bundle that
claims to be offline-verifiable ends up reporting only that an `.ots` file is
present — which is not a fact about Bitcoin.

The missing input is small. A block header is 80 bytes, so it ships too.

```
python3 fetch_headers.py --from 957788 --to 966218 --out headers.bin   # build time, online
python3 verify_anchors.py --export ./export --headers headers.bin      # offline
```

```
headers: 31, heights 957880..957910
chain linkage: PASS
proof of work: PASS, every header meets its stated target
anchor hash at 957905: PASS

anchors: 6 of 838 proofs replay to a merkle root in these headers.
  1 carry no Bitcoin attestation yet (calendar pending).
```

`ots.py` replays the proof: start at the file's digest, apply the append, prepend
and hash operations the proof carries, and arrive at a value the attestation says
is a block's merkle root. `verify_anchors.py` then checks that value against the
header at the height the attestation names, and separately checks that the
headers form a chain — each one's prev-block field is the hash of the one before
— and that every header meets the difficulty it states.

`fetch_headers.py` is the only part that touches the network, and it runs when
the export is built, never when it is verified. It walks backwards from a known
block using each header's own prev-block field, so the run it writes is linked by
construction. It is paced and backs off on HTTP 429, and it saves progress as it
goes, so a rate-limited run resumes instead of starting over.

## What this proves

That the log's checkpoint at some tree size was hashed into a Bitcoin block, so
the log cannot have produced that root any later than that block. Backdating a
checkpoint means producing a chain of headers that meets the stated difficulty.

## What it does not

That these headers are Bitcoin's main chain. A linked run that meets its own
difficulty is work, not consensus, and an export cannot carry enough chain to
settle that. If you already know one block hash from anywhere else, pass it:

```
python3 verify_anchors.py --export ./export --headers headers.bin \
    --expect-hash 957905:0000000000000000000010dd80549f61535150faa6c9c252349b92e34a687442
```

It also says nothing about whether the log served the same tree to everyone.
That is what witness cosignatures are for, and `tlogsearch.py` reports them.
