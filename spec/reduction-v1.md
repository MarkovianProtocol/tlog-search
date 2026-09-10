# Reduction v1

A reduction is a function from a transparency log's leaves to a table.

Publish the function and the table stops needing trust of its own: anyone
replays the leaves in index order, applies it, gets the same rows, and checks
them against a witness-cosigned root. A wrong row becomes a provable defect
rather than the operator's word against yours.

This document specifies one such function, `reduction/v1`, over
`markovianprotocol.com/log`. Its key is `(issuer, subject)`.

Everything below is stated against the live log at tree size 7898, root
`w4EgQfjRRVBy+JSSs8o4H2M0IEMJHeJ0msSDjHhu7Bg=`. The counts are measured, not
assumed.

## 0. What this is not

It is not a database of what is true. A log records what was said. A row in a
table with a hash beside it reads far more like adjudication than the same claim
does as raw leaf bytes, and it is exactly as unverified. This is a harm the
reduction introduces and does not fix.

It is not a content index. 1005 leaves carry no claim type at all and 1060 have
no usable subject; for those the reduction can say what was committed and where
in the sequence, never what it said.

It is not complete. It is a function of the leaves you were shown. An operator
that serves a fully cosigned checkpoint and never accepts your submission
produces a perfect table that omits you.

## 1. Input

The domain is raw leaf bytes, indexed from 0, in index order. Not parsed JSON —
two parsers differ, so parsing is one of the rules rather than a step before
them.

## 2. Parse

`parse(bytes) -> Value | MALFORMED`

- UTF-8, strict. Invalid sequences are MALFORMED. Replacement characters are
  never substituted; `�` is where two languages diverge in silence.
- JSON per RFC 8259, strict: no trailing commas, no comments, no `NaN`, no
  `Infinity`.
- **Duplicate object keys are MALFORMED.** Python and Go both take last-wins, so
  a divergence here is invisible in testing. Two lines of rule remove the class.
- Numbers are integers in ±2^53. Any fraction or exponent in a key-bearing field
  is MALFORMED: `{"version":3}` and `{"version":3.0}` must not become one row.
- A top-level value that is not an object is MALFORMED.

45 leaves in this log are not JSON. They are `public-note:v1`, and they get a
declared grammar rather than a shrug:

```
^public-note:v1 sha256:[0-9a-f]{64} <RFC3339 UTC>$
```

All 45 match it. Anything matching parses to a note with that digest and
timestamp; anything else claiming to be a note is MALFORMED. "It is obviously a
note" is not a rule.

## 3. Type

`typeof(Value) -> string | UNTYPED`, by explicit ordered lookup:

1. `$.claim_type`, if a string
2. `$.claimType`, if a string
3. `$.core.claimType`, if `$.core` is an object and the field is a string
4. `$.kind`, if a string
5. otherwise UNTYPED

`$.schema` is **not** in this list. It is an envelope version, not a type, and
folding it in silently reclassifies 1005 leaves.

Types are opaque byte strings, compared byte-wise. This log holds 37 distinct
ones, mixing URIs (`https://markovianprotocol.com/claim/signal-commit/v1`) with
bare words (`prediction`, `outcome`). No normalisation, no prefix stripping, no
case folding: `prediction` and `Prediction` are two types.

Why the order is stated rather than "look in the obvious place": four defensible
readings of this one question type between 2950 and 6848 of the same 7898
leaves. The spread is 3898 rows, 49.4% of the log. See `corpus/divergence.py`.

## 4. Issuer

`issuer(Value) -> bytes | NO_KEY`, by ordered lookup:

1. `$.issuer`, if a string — 7700 leaves
2. `$.core.issuer`, if a string — 140 leaves
3. otherwise NO_KEY — 13 leaves

The value is the literal UTF-8 bytes as written. Rotation is handled in §8 and
never here.

## 5. Subject

`subject(Value) -> bytes | NO_KEY`, by ordered lookup:

1. `$.subject`, if a string — 2945 leaves
2. `$.subject.name`, if `$.subject` is an object and `name` is a string — 3753
3. `$.core.subject.name`, under the same condition — 140
4. otherwise NO_KEY — 1060

**A subject object without a `name` is NO_KEY, even when it has a `digest`.**
There is one such leaf, index 1293. Keying on the digest instead would open a
second namespace with no way to tell the two apart afterwards.

Subject bytes are compared raw, with **no Unicode normalisation**. Normalising
merges two visually identical keys, and which one wins then depends on your ICU
version. Two byte-different subjects are two rows.

## 6. Key

```
key = (issuer_bytes, subject_bytes)
```

A leaf with NO_KEY on either side is unkeyable and contributes no row. 6837
leaves — 86.6% — are keyable.

The key is the pair, never the subject alone. 1470 of 5165 distinct subject
names in this log are already claimed by more than one issuer. Keying on the
subject alone would let anyone displace anyone's row by writing later, and the
tool would report the winner with a straight face.

The consequence is a feature and must be stated as one: looking up a subject
returns **every issuer's row for it**, because the log genuinely contains
disagreeing claims. Returning one would be a lie about the log's contents.

## 7. Ordering and conflict

**Order is leaf index. Only leaf index.** Not timestamps: this log carries three
timestamp formats, 3959 leaves have none, and every one that exists is asserted
by the issuer rather than assigned by the log. This is a prohibition, not an
omission — nobody should later "improve" it with `issuedAt`.

Within a key, **last write by index wins**. These are assertions by a party
about its own subject, so first-write-wins would freeze an issuer's first
mistake permanently and make correction impossible.

Each row carries `first_index`, `last_index`, `superseded_count`, and the
`leaf_sha256` of the winning leaf, so every row points at a leaf that has an
inclusion proof. Superseded leaves are counted, never dropped silently.

## 8. Retraction, not deletion

There is no delete. An append-only log cannot forget, and a reduction that
pretends otherwise hands back exactly the power the log exists to remove: an
operator who can delete rows can present a clean table while the log stays
perfectly consistent, and nobody looks.

A retraction sets `state: retracted` and records `retracted_at_index`, and the
prior value stays queryable. Default views show retracted rows flagged, not
absent.

Only the issuer that wrote the row may retract it, matched on issuer bytes.

**No retraction claim type exists in this log today** — zero instances across
all 37 types. The rule is specified now so the first one is not an emergency.

## 9. Rotation, forward only

Leaf 1728 is a `key-rotation/v1` claim whose `issuer` is the **old** DID.

1. A rotation applies only to leaves at index **greater than its own**. Never
   backwards. Applied backwards, whoever writes a rotation leaf inherits every
   row its predecessor ever wrote.
2. It must be signed by the outgoing key. Leaf 1728 carries `rotation_sig`
   already; this codifies the existing practice rather than inventing one.
3. Rotating an identity with no prior rows is a no-op, not an error.
4. The `identity_graph` is emitted alongside the table, so the chain stays
   inspectable instead of folded away.

This is the rule most likely to be implemented differently by a second party,
and it should be a large share of the corpus.

## 10. Accounting

MALFORMED leaves are counted, never skipped: `malformed: [indices]`.
UNTYPED and unkeyable leaves are counted by reason: `skipped: {reason: count}`.

The rule that makes this honest:

> **A result carrying any malformed or skipped leaf cannot answer a question
> about absence.**

A skipped leaf might have been the row you asked for. This is the existing
`tlogsearch` rule — a search over part of a tree says nothing about absence —
extended from a partial *tree* to a partial *interpretation*. Positive hits are
still returned: a hit proves itself, a miss does not.

## 11. Output

- Rows sorted by `(issuer_bytes, subject_bytes)`, byte-wise ascending. Not
  locale collation.
- Each row serialised as RFC 8785 (JCS) canonical JSON — already the log's
  canonicalisation, and conformance-tested across Python and Node in
  `MarkovianProtocol/canoncheck`.
- Newline-delimited, LF only, trailing newline.
- `table_sha256` is SHA-256 over that serialisation.

An answer is never a table. It is:

```
(root_b64, tree_size, reduction_sha256, table_sha256)
+ {malformed: [...], skipped: {...}, witnesses: n, quorum: q}
```

A table handed over without that quad is a database again.

## 12. Refusals

Exit 2, in the register the existing tools use.

1. Bundle holds fewer leaves than the checkpoint commits.
2. Leaf indices are not `0..size-1` with no gaps.
3. Recomputed root does not match the checkpoint.
4. No valid log signature; no stated quorum; or verified independent
   cosignatures below that quorum.
5. `reduction_sha256` not committed in-log at or before `tree_size`. An
   uncommitted reduction is the operator's opinion about the operator's data.
6. An absence question while `malformed` or `skipped` is non-empty.
7. A single-row query on a contested key. Return the set or refuse; never pick.
   With 1470 contested keys this fires often, and that is correct.
8. **"As of time T", always.** Only "as of tree size N". A time-indexed answer
   over this log would be a fabrication with a hash on it. Permanent, not
   pending better data.
9. A reduction version mismatch. A client asking under v1 gets v1 or nothing;
   never a translation.
10. A leaf shape no rule covers — refuse and name the index. Guessing at a novel
    shape silently chooses a table, and refusing is how a new claim type gets
    noticed instead of absorbed.
11. Truncated output without a true total.

## 13. Versioning

The reduction's own hash goes in the log, reusing the trust-root manifest shape
that already exists at leaves 6101 and 6112:

```json
{"claim_type": "reduction-manifest/v1",
 "reduction_sha256": "<sha256 of this document's canonical bytes>",
 "corpus_sha256": "<sha256 of corpus/cases.json>",
 "url": "https://markovianprotocol.com/.well-known/reduction/1.json",
 "version": 1}
```

Same rotation rule as the trust root: version exactly one greater,
`previous_reduction_sha256` chaining to its predecessor, and the manifest leaf
must sit under a checkpoint cosigned to quorum. No new mechanism and no new
trust assumption.

`reduction-manifest/v1` leaves are **excluded from the reduction's own key
space**. Including them makes the function self-referential with no clean fixed
point.

`corpus_sha256` is committed alongside so the tests cannot be quietly weakened
while the prose stays put.

A new version **re-derives from index 0**. Forward-splicing — old rows under v1,
new rows under v2 — would make the table a function of the operator's release
timeline, which is unauditable and operator-controlled. That is affordable only
because full replay of this log takes 0.08s; at 22.6 leaves/day it stays
affordable for decades.

Old answers stay true. `(root, 7898, v1, T1)` is a fact about a function over
those leaves forever. `(root, 7898, v2, T2)` is also a fact. Two reductions are
two questions, not a contradiction.

A version is answerable only for `tree_size >= the index of its manifest leaf`.

## 14. What is standard here, and what is not

Deterministic replay of a log into a materialised view is event sourcing, and it
is decades old. Binding a view to a cosigned root is Certificate Transparency,
and CT monitors have indexed tiles for years. Last-write-wins registers and
tombstones are CRDT basics. None of that is a claim.

Two things are less common. Committing the reduction's hash *in the log it
reads*, so the interpretation is as auditable as the data — CT monitors do not
do this, and there is no way to check that crt.sh reduced correctly because
there is no published function to check against. And the refusal semantics in
§10 and §12: an index that tells you when it cannot answer, rather than one that
silently drops what it could not parse.

The second is the smaller claim and the more useful one.
