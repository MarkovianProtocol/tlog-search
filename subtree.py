"""Subtree hashes and subtree consistency proofs, for c2sp.org/tlog-mirror.

A mirror is a cosigner that additionally asserts it has durably stored a log's
contents and serves them. Feeding one means uploading entries in packages of
256, each carrying a subtree consistency proof so the mirror can verify and
commit a package without buffering the whole upload.

Generation and verification follow draft-ietf-plants-merkle-tree-certs-02
sections 4.1, 4.4.1 and 4.4.3. Stdlib only.

The two procedures are deliberately written from opposite ends -- generation
recursive as the draft defines it, verification iterative as the draft defines
it -- so that agreeing is evidence rather than a shared bug.
"""
import hashlib


def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n):
    """The largest power of two smaller than n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def bit_ceil(x):
    """Smallest power of two >= x."""
    k = 1
    while k < x:
        k *= 2
    return k


def mth(hashes):
    """RFC 9162 Merkle Tree Hash over a list of leaf hashes."""
    if not hashes:
        return hashlib.sha256(b"").digest()
    if len(hashes) == 1:
        return hashes[0]
    k = _split(len(hashes))
    return node_hash(mth(hashes[:k]), mth(hashes[k:]))


def valid_subtree(start, end, n):
    """Section 4.1: 0 <= start < end <= n, and start is a multiple of
    BIT_CEIL(end - start)."""
    if not (0 <= start < end <= n):
        return False
    return start % bit_ceil(end - start) == 0


def subtree_proof(start, end, hashes):
    """Section 4.4.1: SUBTREE_PROOF(start, end, D_n)."""
    n = len(hashes)
    if not valid_subtree(start, end, n):
        raise ValueError("[%d, %d) is not a valid subtree of %d" % (start, end, n))
    return _subproof(start, end, hashes, True)


def _subproof(start, end, hashes, b):
    n = len(hashes)
    if start == 0 and end == n:
        return [] if b else [mth(hashes)]
    k = _split(n)
    if end <= k:
        return _subproof(start, end, hashes[:k], b) + [mth(hashes[k:])]
    if k <= start:
        return _subproof(start - k, end - k, hashes[k:], b) + [mth(hashes[:k])]
    # start < k < end implies start == 0
    return _subproof(0, end - k, hashes[k:], False) + [mth(hashes[:k])]


def verify_subtree_proof(start, end, n, proof, node_hash_value, root_hash):
    """Section 4.4.3. Returns True only if the proof ties the subtree hash to
    the root hash over exactly the entries in [start, end)."""
    if not valid_subtree(start, end, n) or end > n:
        return False
    fn, sn, tn = start, end - 1, n - 1

    if sn == tn:
        while fn != sn:
            fn >>= 1; sn >>= 1; tn >>= 1
    else:
        while fn != sn and (sn & 1):
            fn >>= 1; sn >>= 1; tn >>= 1

    proof = list(proof)
    if fn == sn:
        fr = sr = node_hash_value
    else:
        if not proof:
            return False
        fr = sr = proof.pop(0)

    for c in proof:
        if tn == 0:
            return False
        if (sn & 1) or sn == tn:
            if fn < sn:
                fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not (sn & 1):
                fn >>= 1; sn >>= 1; tn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1; sn >>= 1; tn >>= 1

    return tn == 0 and fr == node_hash_value and sr == root_hash
