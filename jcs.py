"""Minimal RFC 8785 (JCS) serializer for the subset used by these vectors.

Supports: dict, list, str, bool, None, int. Floats are rejected rather than
approximated -- RFC 8785 number serialization is the ES6 algorithm and getting
it subtly wrong is worse than refusing. No audit attribute in the OTel draft
requires a float.
"""


def _esc(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif o == 0x08:
            out.append('\\b')
        elif o == 0x0C:
            out.append('\\f')
        elif o == 0x0A:
            out.append('\\n')
        elif o == 0x0D:
            out.append('\\r')
        elif o == 0x09:
            out.append('\\t')
        elif o < 0x20:
            out.append('\\u%04x' % o)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _utf16_key(s):
    # RFC 8785 sorts object members by their UTF-16 code units, big-endian.
    return list(s.encode('utf-16-be'))


def dumps(obj):
    if obj is True:
        return 'true'
    if obj is False:
        return 'false'
    if obj is None:
        return 'null'
    if isinstance(obj, str):
        return _esc(obj)
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        raise TypeError('float not supported by this JCS subset')
    if isinstance(obj, list):
        return '[' + ','.join(dumps(x) for x in obj) + ']'
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: _utf16_key(kv[0]))
        return '{' + ','.join(_esc(k) + ':' + dumps(v) for k, v in items) + '}'
    raise TypeError('unsupported type: %r' % type(obj))


def encode(obj):
    return dumps(obj).encode('utf-8')
