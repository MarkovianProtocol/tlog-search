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
