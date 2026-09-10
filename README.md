# tlog-search

Tools for a transparency log, all stdlib-only Python, no dependencies and no
network unless a line below says otherwise.

| | |
|---|---|
| `tlogsearch.py` | Search an export. A miss is a claim, not an empty result. |
| `reduce.py` | Reduce the log to a table by a published function. Point-in-time answers, and receipts. |
| `verify_receipt.py` | Check one row from the receipt alone — inclusion, root, cosignatures, and that the row re-derives. |
| `subtree.py` | Subtree hashes and consistency proofs (MTC draft §4.1, §4.4). Byte-identical to torchwood. |
| `mirror_client.py` | Feed a log to a `c2sp.org/tlog-mirror` mirror. |
| `ots.py` | Replay an OpenTimestamps proof. |
| `verify_anchors.py` | Check a bundle's Bitcoin anchors against shipped headers, offline. |
| `fetch_headers.py` | Collect those headers. The only part that uses the network. |
| `git_attest.py` | Record a commit and its signature status from a local clone. |
| `attest_repos.py` | Record what a git host serves for every repo in an org. |
| `hf_attest.py` | Record what Hugging Face serves for a model. |
| `hf_watch.py` | Watch a model set daily: one digest leaf per run, a detail leaf per change. |

---

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

It also refuses a checkpoint it cannot hold to a standard: no valid log
signature, no witness quorum stated in the trust root, or fewer verified
independent cosignatures than that quorum.

```
REFUSING TO SEARCH: 1 independent witness cosignature(s), quorum is 4.
A tree only one party vouches for cannot tell you what is absent from it.
```

Cosignatures from keys the signed trust root does not name are reported and
never counted toward the quorum.

Exit is 0 on a verified search and 2 on any refusal.

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

---

# Reducing the log to a table

A log is a sequence, not a database: no keys, no updates, no queries. The usual
fix is an index, and an index is the operator's word — which is the power the log
was built to remove, re-entering through the back.

`reduce.py` implements `spec/reduction-v1.md`: a stated function from the leaves
to a table, keyed on `(issuer, subject)`. Replay the leaves in index order, apply
it, and you get the same rows anyone else gets, checked against the same cosigned
root.

```
python3 reduce.py --export ./export
python3 reduce.py --export ./export --subject bitcoin-block-957803
python3 reduce.py --export ./export --table rows.jsonl
```

Over the live log at 7898 leaves: 6780 rows, 0 malformed, and a `table_sha256`
that is byte-identical across runs.

An answer is never a bare table. It is the quad:

```
root             w4EgQfjRRVBy+JSSs8o4H2M0IEMJHeJ0msSDjHhu7Bg=
tree_size        7898
reduction_sha256 c5dea0c10a057d5365faac5658a5c6f9a9b0a562e61121333e70173293281d40
table_sha256     ee4fb4d4cf25b63abe4bf9f7cbea83db450030461198dd70d019fe3579e86be0
```

`reduction_sha256` goes in the log itself, as a `reduction-manifest/v1` leaf, so
the interpretation is as auditable as the data. An uncommitted reduction is the
operator's opinion about the operator's data.

For this log that leaf is at index 7912. A manifest counts only once a
quorum-cosigned checkpoint actually covers its index — being appended is not the
same as being witnessed, and the spec refuses on the difference.

## The key is the pair

Never the subject alone. 1470 of 5165 distinct subject names in this log are
already claimed by more than one issuer, so a bare-subject key would let anyone
displace anyone's row by writing later.

So a subject lookup returns every issuer's row for it, and says why:

```
{"claim_type":"prediction","issuer":"anon38c830fa…","subject":"bitcoin-block-957803",…}
{"claim_type":"outcome","issuer":"anon9716a032…","subject":"bitcoin-block-957803",…}

2 issuers claim this subject. This is not a tie to be broken;
the log holds 2 disagreeing claims about it.
```

## It says when it cannot answer

```
This result cannot answer a question about absence: 1061 leaves were
malformed or skipped, and any one of them might have been the row
you asked for. Hits above are still hits; a miss is not a miss.
```

That is the whole point, and it is the part no other log index does. Every one of
them silently drops what it could not parse, and then answers your question as if
it hadn't.

`corpus/` holds the adversarial cases from the real log, and measures what an
unwritten rule costs: four defensible readings of "what type is this leaf" type
between 2950 and 6848 of the same 7898 leaves — a spread of 49.4%.


---

# Recording what a host said

A signature says who. It does not say when — commit dates are chosen by whoever
makes the commit, and the signature covers the values they chose — and it does
not say this is the only version published, because a signed commit can be
force-pushed away and replaced by another signed commit with nothing in either
signature revealing it.

Neither is fixed by signing harder. Both need a record kept where the committer
has no control, at a time they do not pick.

```
python3 git_attest.py --repo . --rev HEAD
python3 attest_repos.py --org YOURORG --out leaves/
python3 hf_attest.py --models models.txt --out leaves/
python3 hf_watch.py --models models.txt --state state.json --submit
```

These record what was observed rather than vouching for it. An unverified
signature, or a model card behind a gate, is a fact worth logging — not a reason
to refuse.

## Why it matters, with a real case

```
leaf 7942  git:github.com/MarkovianProtocol/tlog-search@2af8946c  unknown_key
leaf 7944  git:github.com/MarkovianProtocol/tlog-search@2af8946c  valid
```

Same commit, same tree, same parents, same dates. A signing key was registered
between the two observations, and the host's verdict about an immutable object
moved with it. Ask today and you get the second answer, with nothing indicating
there was a first.

Nobody staged that. It happened while setting up commit signing on this repo.

## Watching without burying the log

`hf_watch.py` writes one digest leaf per run — the count, the failures, and a
hash over every watched model's state — and a detail leaf only for a model whose
head, card digest, or gated state moved.

Logging everything every run would add thousands of identical leaves a year and
bury the few that matter. Logging only changes would make silence meaningless,
since a model with no leaf might be unchanged or might never have been looked
at. This way a quiet day is on the record and a change always has its own leaf.

The watched list is in `models.txt`, published so the selection cannot be said to
have been made after the fact.
