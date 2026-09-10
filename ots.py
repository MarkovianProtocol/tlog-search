"""OpenTimestamps proof parsing and replay. Stdlib only.

An .ots proof is a hash chain: start from the digest of the file, apply a list of
append/prepend/hash operations, and arrive at a value that some attestation
claims is committed somewhere. For a Bitcoin attestation, that value is a block's
merkle root and the attestation names the height.

This module does the replay. It does not fetch anything, and it does not decide
whether a block is real -- see verify_anchors.py for that half.

Format: https://github.com/opentimestamps/python-opentimestamps
"""
import hashlib

MAGIC = (b"\x00OpenTimestamps\x00\x00Proof\x00"
         b"\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

OP_SHA1 = 0x02
OP_RIPEMD160 = 0x03
OP_SHA256 = 0x08
OP_KECCAK256 = 0x67
OP_APPEND = 0xf0
OP_PREPEND = 0xf1
OP_REVERSE = 0xf2
OP_HEXLIFY = 0xf3
OP_FORK = 0xff
OP_ATTESTATION = 0x00

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_LITECOIN = bytes.fromhex("06869a0d73d71b45")
TAG_ETHEREUM = bytes.fromhex("30fe8087b5c7ead7")

TAG_NAMES = {
    TAG_BITCOIN: "bitcoin",
    TAG_PENDING: "pending",
    TAG_LITECOIN: "litecoin",
    TAG_ETHEREUM: "ethereum",
}


class OTSError(Exception):
    pass


class _Reader:
    def __init__(self, buf):
        self.buf = buf
        self.i = 0

    def byte(self):
        if self.i >= len(self.buf):
            raise OTSError("truncated proof")
        b = self.buf[self.i]
        self.i += 1
        return b

    def take(self, n):
        if self.i + n > len(self.buf):
            raise OTSError("truncated proof")
        out = self.buf[self.i:self.i + n]
        self.i += n
        return out

    def varuint(self):
        val, shift = 0, 0
        while True:
            b = self.byte()
            val |= (b & 0x7f) << shift
            if not b & 0x80:
                return val
            shift += 7
            if shift > 63:
                raise OTSError("varuint too long")

    def varbytes(self):
        return self.take(self.varuint())

    def done(self):
        return self.i >= len(self.buf)


def _ripemd160(b):
    try:
        h = hashlib.new("ripemd160")
    except ValueError:
        raise OTSError("ripemd160 unavailable in this Python's hashlib")
    h.update(b)
    return h.digest()


def _apply(op, arg, msg):
    if op == OP_APPEND:
        return msg + arg
    if op == OP_PREPEND:
        return arg + msg
    if op == OP_REVERSE:
        return msg[::-1]
    if op == OP_HEXLIFY:
        return msg.hex().encode()
    if op == OP_SHA256:
        return hashlib.sha256(msg).digest()
    if op == OP_SHA1:
        return hashlib.sha1(msg).digest()
    if op == OP_RIPEMD160:
        return _ripemd160(msg)
    if op == OP_KECCAK256:
        raise OTSError("keccak256 is not in the standard library")
    raise OTSError("unknown operation 0x%02x" % op)


def _walk(r, msg, out):
    """Replay one branch, recording every attestation it reaches."""
    while True:
        if r.done():
            return
        op = r.byte()
        if op == OP_FORK:
            # Each branch continues from the same message. Parse them in turn;
            # the last one runs on after the fork ends.
            _walk(r, msg, out)
            continue
        if op == OP_ATTESTATION:
            tag = r.take(8)
            payload = r.varbytes()
            rec = {"tag": tag, "name": TAG_NAMES.get(tag, "unknown:" + tag.hex()),
                   "message": msg}
            if tag == TAG_BITCOIN:
                rec["height"] = _Reader(payload).varuint()
            elif tag == TAG_PENDING:
                rec["uri"] = _Reader(payload).varbytes().decode("utf-8", "replace")
            out.append(rec)
            return
        arg = b""
        if op in (OP_APPEND, OP_PREPEND):
            arg = r.varbytes()
        msg = _apply(op, arg, msg)


def parse(data):
    """Return (file_digest, attestations).

    Each attestation is a dict with name, message (the value it commits to), and
    for bitcoin a height. `message` for a bitcoin attestation is the block's
    merkle root, in internal byte order.
    """
    if not data.startswith(MAGIC):
        raise OTSError("not an OpenTimestamps proof")
    r = _Reader(data[len(MAGIC):])
    version = r.varuint()
    if version != 1:
        raise OTSError("unsupported proof version %d" % version)
    op = r.byte()
    sizes = {OP_SHA1: 20, OP_RIPEMD160: 20, OP_SHA256: 32, OP_KECCAK256: 32}
    if op not in sizes:
        raise OTSError("unknown file hash operation 0x%02x" % op)
    digest = r.take(sizes[op])
    out = []
    _walk(r, digest, out)
    return digest, out


def bitcoin_attestations(data):
    digest, ats = parse(data)
    return digest, [a for a in ats if a["tag"] == TAG_BITCOIN]
