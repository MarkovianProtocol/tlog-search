# The corpus

A reduction is a function from a log's leaves to a table. Publish it and anyone
replays the leaves, applies it, gets the same table, and checks it against the
cosigned root — the table has no trust of its own, and a wrong row is a provable
defect rather than the operator's word.

That only holds if the function is actually pinned down. A spec written in prose
is not pinned down; ambiguity is indistinguishable from a backdoor, because every
unstated case is one the operator gets to decide after the fact.

So the spec is not the defence. The corpus is.

## The cost of an unwritten rule, measured

`divergence.py` runs four readings of one question — *what type is this leaf* —
over all 7898 leaves of the live export. Each is defensible after skimming a few
leaves.

```
dispatch rule               typed   missed  distinct types
claim_type only              2950     4948  6
claimType only               3756     4142  21
either spelling              6706     1192  27
stated dispatch order        6848     1050  35
```

The spread between the most and least generous reading is **3898 leaves, 49.4% of
the log**. Two honest implementations disagree about half the table, and nothing
adjudicates between them.

```
python3 divergence.py --export /path/to/log-terminal-export
```

## The cases

`cases.json` holds real leaves from the live log — nothing invented — with the
property that makes each one awkward. It pins the root and tree size they were
drawn from, so the cases can be located in the log itself.

- **plaintext-notes** — leaves 7443–7447 are not JSON. They are
  `public-note:v1 sha256:<digest> <timestamp>`, and they all commit the *same*
  document digest at different times, so their leaf hashes differ. A reduction
  needs a declared byte grammar for these or must call them malformed. "It is
  obviously a note" is not a rule.
- **key-rotation** — leaf 1728 rotates one DID to another, and its `issuer` is
  the *old* DID. Applied backwards, a rotation leaf re-attributes every row its
  predecessor ever wrote, so whoever can write one inherits another issuer's
  history. It must bind forward only, from indices above its own.
- **typed-via-\*** — the same question answered through `claim_type`,
  `claimType`, `core.claimType`, `kind`, and not at all.
- **subject-\*** — `subject` is a dict 3754 times, a bare string 2945 times, and
  absent 1154 times. Generic key extraction is not possible.

## What this is for

A second implementation that reproduces the same output on these cases has
demonstrated agreement. One that has merely read a specification has not. This is
how Certificate Transparency got interoperability, and there is no cheaper
substitute.

The corpus also decides the design. Writing it first tells you which rules you
cannot actually state yet — and a case you cannot state is a case the tool should
refuse, not guess.
