"""Pure-Python Ed25519 (RFC 8032) sign and verify. No dependencies.

Straightforward reference arithmetic -- correctness over speed. Used here so a
verifier runs on a stock python3 with nothing installed.
"""
import hashlib

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def H(m):
    return hashlib.sha512(m).digest()


def inv(x):
    return pow(x, q - 2, q)


d = -121665 * inv(121666) % q
I = pow(2, (q - 1) // 4, q)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * inv(5) % q
Bx = xrecover(By)
B = (Bx % q, By % q, 1, (Bx * By) % q)


def edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % q
    bb = (y1 + x1) * (y2 + x2) % q
    c = t1 * 2 * d * t2 % q
    dd = z1 * 2 * z2 % q
    e, f, g, h = bb - a, dd - c, dd + c, bb + a
    return (e * f % q, g * h % q, f * g % q, e * h % q)


def edwards_double(P):
    # dbl-2008-hwcd for the a = -1 twisted Edwards curve.
    x1, y1, z1, _ = P
    a = x1 * x1 % q
    bb = y1 * y1 % q
    c = 2 * z1 * z1 % q
    dd = -a % q
    e = ((x1 + y1) * (x1 + y1) - a - bb) % q
    g = (dd + bb) % q
    f = (g - c) % q
    h = (dd - bb) % q
    return (e * f % q, g * h % q, f * g % q, e * h % q)


def scalarmult(P, e):
    if e == 0:
        return (0, 1, 1, 0)
    Q = scalarmult(P, e // 2)
    Q = edwards_double(Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q


def encodeint(y):
    return y.to_bytes(32, 'little')


def encodepoint(P):
    x, y, z, _ = P
    zi = inv(z)
    x = x * zi % q
    y = y * zi % q
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, 'little')


def _clamp(h):
    a = 2 ** (b - 2) + sum(2 ** i for i in range(3, b - 2) if (h[i // 8] >> (i % 8)) & 1)
    return a


def publickey(sk):
    h = H(sk)
    a = _clamp(h)
    return encodepoint(scalarmult(B, a))


def signature(m, sk, pk):
    h = H(sk)
    a = _clamp(h)
    r = int.from_bytes(H(h[32:64] + m), 'little') % l
    R = scalarmult(B, r)
    Rb = encodepoint(R)
    k = int.from_bytes(H(Rb + pk + m), 'little') % l
    S = (r + k * a) % l
    return Rb + encodeint(S)


def isoncurve(P):
    x, y, z, t = P
    return (z % q != 0 and x * y % q == z * t % q and
            (y * y - x * x - z * z - d * t * t) % q == 0)


def decodeint(s):
    return int.from_bytes(s, 'little')


def decodepoint(s):
    y = int.from_bytes(s, 'little') & ((1 << 255) - 1)
    x = xrecover(y)
    if x & 1 != (s[31] >> 7) & 1:
        x = q - x
    P = (x, y, 1, x * y % q)
    if not isoncurve(P):
        raise ValueError('decoding point that is not on curve')
    return P


def checkvalid(sig, m, pk):
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        R = decodepoint(sig[0:32])
        A = decodepoint(pk)
    except ValueError:
        return False
    S = decodeint(sig[32:64])
    if S >= l:
        return False
    k = int.from_bytes(H(sig[0:32] + pk + m), 'little') % l
    lhs = scalarmult(B, S)
    rhs = edwards_add(R, scalarmult(A, k))
    return encodepoint(lhs) == encodepoint(rhs)
