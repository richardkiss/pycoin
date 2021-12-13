from pycoin.encoding.b58 import a2b_base58
from pycoin.encoding.hash import double_sha256
from pycoin.contrib import bech32m
from pycoin.intbytes import int2byte


class parseable_str(str):
    """
    This is a subclass of str which allows caching of parsed base58 and bech32
    data (or really anything) to eliminate the need to repeatedly run slow parsing
    code when checking validity for multiple types.
    """
    def __new__(self, s):
        if isinstance(s, parseable_str):
            return s
        return str.__new__(self, s)

    def __init__(self, s):
        super(str, self).__init__()
        if isinstance(s, parseable_str):
            self._cache = s._cache
        else:
            self._cache = {}

    def cache(self, key, f):
        if key not in self._cache:
            self._cache[key] = None
            try:
                self._cache[key] = f(self)
            except Exception:
                pass
        return self._cache[key]


def parse_b58(s):
    s = parseable_str(s)
    return s.cache("b58", a2b_base58)


def b58_double_sha256(s):
    data = parse_b58(s)
    if data:
        data, the_hash = data[:-4], data[-4:]
        if double_sha256(data)[:4] == the_hash:
            return data


def parse_b58_double_sha256(s):
    s = parseable_str(s)
    return s.cache("b58_double_sha256", b58_double_sha256)


def parse_bech32_or_32m(s):
    triple = bech32m.bech32_decode(s)
    if triple is None or triple[1] is None:
        return None
    hr_prefix = triple[0]
    data = triple[1]
    spec = triple[2]
    version = data[0]
    decoded = bech32m.convertbits(data[1:], 5, 8, False)
    decoded_data = b''.join(int2byte(d) for d in decoded)
    rv = (hr_prefix, version, decoded_data, spec)
    return rv


def parse_bech32(s):
    s = parseable_str(s)
    return s.cache("bech32", parse_bech32_or_32m)


def parse_colon_prefix(s):
    s = parseable_str(s)
    return s.cache("colon_prefix", lambda _: _.split(":", 1))
