#!/usr/bin/env python3
"""Show what an unwritten reduction rule costs, using the real log.

A reduction is a function from a log's leaves to a table. If the function is
not written down, two honest implementations disagree, and the operator gets to
pick which answer is "the" answer. That is the power a transparency log exists
to remove, re-entering through the index.

This is not a hypothetical. Below are four dispatch rules, each of which a
competent engineer might write after reading a handful of leaves, run against
every leaf in a real export. They do not differ at the margin.

    python3 divergence.py --export ../../projects/log-terminal-export
"""
import argparse
import base64
import collections
import json
import os


def leaves(export):
    with open(os.path.join(export, "leaves.jsonl")) as fh:
        for line in fh:
            line = line.strip()
            if line:
                r = json.loads(line)
                yield r["index"], base64.b64decode(r["data_b64"])


def as_obj(data):
    try:
        o = json.loads(data)
    except Exception:
        return None
    return o if isinstance(o, dict) else None


# Four readings of "what type is this leaf". Each is defensible in isolation.
def rule_snake(o):
    return o.get("claim_type") if o else None


def rule_camel(o):
    return o.get("claimType") if o else None


def rule_either(o):
    if not o:
        return None
    return o.get("claim_type") or o.get("claimType")


def rule_full(o):
    """The dispatch order a spec would have to state: explicit, ordered, total."""
    if not o:
        return None
    for path in (("claim_type",), ("claimType",), ("core", "claimType"), ("kind",)):
        v = o
        for p in path:
            v = v.get(p) if isinstance(v, dict) else None
        if isinstance(v, str):
            return v
    return None


RULES = [("claim_type only", rule_snake),
         ("claimType only", rule_camel),
         ("either spelling", rule_either),
         ("stated dispatch order", rule_full)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export", default=".")
    a = ap.parse_args()

    typed = collections.Counter()
    total = 0
    per_rule_types = collections.defaultdict(set)
    for _, data in leaves(a.export):
        total += 1
        o = as_obj(data)
        for name, fn in RULES:
            t = fn(o)
            if t is not None:
                typed[name] += 1
                per_rule_types[name].add(t)

    print("%d leaves\n" % total)
    print("%-24s %8s %8s  %s" % ("dispatch rule", "typed", "missed", "distinct types"))
    for name, _ in RULES:
        print("%-24s %8d %8d  %d"
              % (name, typed[name], total - typed[name], len(per_rule_types[name])))

    best = max(typed.values())
    worst = min(typed.values())
    print("\nSpread between the most and least generous reading: %d leaves, "
          "%.1f%% of the log." % (best - worst, 100.0 * (best - worst) / total))
    print("Every one of those is a row that exists in one implementation's table")
    print("and not in another's, with no way to say which is correct, because")
    print("nobody wrote the rule down.")
    print()
    print("Note what the fullest rule still leaves untyped: those leaves are not")
    print("errors, they are a shape the rule does not cover. A reduction that")
    print("silently drops them can still answer a question about presence, and")
    print("cannot honestly answer one about absence.")


if __name__ == "__main__":
    main()
