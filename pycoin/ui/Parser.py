from collections import defaultdict

from pycoin.encoding.b58 import a2b_base58, a2b_hashed_base58, EncodingError
from pycoin.encoding.hash import double_sha256
from pycoin.contrib import segwit_addr

"""
INFO:

type: key, address, spendable, etc.
create_f: call to create a canonical instance of what this represents

KEY:
  key_type: bip32, wif, sec
  is_private: True or False
  kwargs: passed to constructor
  key_class: the class


"""


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


def parse_bech32(s):
    s = parseable_str(s)
    return s.cache("bech32", segwit_addr.bech32_decode)


def parse_colon_prefix(s):
    s = parseable_str(s)
    return s.cache("colon_prefix", lambda _: _.split(":", 1))
