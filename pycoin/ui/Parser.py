from collections import defaultdict

from pycoin.encoding.b58 import a2b_base58, a2b_hashed_base58, b2a_base58, EncodingError
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


def metadata_for_text(text):
    d = {}
    try:
        data = a2b_hashed_base58(text)
        d["as_base58"] = (data,)
    except EncodingError:
        d["as_base58"] = None

    try:
        hrp, data = segwit_addr.bech32_decode(text)
        if None not in [hrp, data]:
            d["as_bech32"] = (hrp, data)
        else:
            d["as_bech32"] = None
    except (TypeError, KeyError):
        pass

    try:
        prefix, rest = text.split(":", 1)
        data = rest
        d["as_colon"] = (prefix, data)
    except ValueError:
        d["as_colon"] = None

    d["as_text"] = (text, )
    return d


def parse_all_to_info(metadata, parsers):
    # TODO: simplify, and put the "type" field into info here
    for key in ["as_base58", "as_bech32", "as_colon", "as_text"]:
        v = metadata.get(key)
        if v is None:
            continue
        for p in parsers:
            f_name = "_parse_%s" % key
            f = getattr(p, f_name)
            for _ in f(*v):
                yield _


def parse_to_info(metadata, parsers):
    for r in parse_all_to_info(metadata, parsers):
        return r


def parse_all(item, parsers):
    metadata = metadata_for_text(item)
    for info in parse_all_to_info(metadata, parsers):
        yield info.get("create_f")()


def parse(item, parsers):
    for r in parse_all(item, parsers):
        return r


def make_base58_prefixes(prefix_f_list):
    d = defaultdict(lambda: defaultdict(list))
    for prefix, f in prefix_f_list:
        d[len(prefix)][prefix].append(f)
    return d


class Parser(object):

    TYPE = None

    _base58_prefixes = make_base58_prefixes([])
    _bech32_prefixes = defaultdict(list)
    _colon_prefixes = defaultdict(list)

    def _parse_as_base58(self, data):
        for size, lookup in self._base58_prefixes.items():
            prefix = data[:size]
            for f in lookup.get(prefix, []):
                try:
                    yield f(data)
                except Exception:
                    pass

    def _parse_as_bech32(self, hrp, data):
        for f in self._bech32_prefixes.get(hrp, []):
            try:
                yield f(hrp, data)
            except Exception:
                pass

    def _parse_as_colon(self, hrp, data):
        for f in self._colon_prefixes.get(hrp, []):
            try:
                yield f(hrp, data)
            except Exception:
                pass

    def _parse_as_text(self, text):
        return []
