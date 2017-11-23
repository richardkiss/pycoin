from pycoin import encoding
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


def metadata_for_text(text):
    d = {}
    try:
        data = encoding.a2b_hashed_base58(text)
        d["as_base58"] = (data,)
    except encoding.EncodingError:
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


def _parse_base58(parser, metadata):
    r = metadata.get("as_base58")
    if not r:
        return
    data = r[0]
    base58_prefixes = parser.base58_prefixes()
    for size in base58_prefixes.keys():
        prefix = data[:size]
        f = base58_prefixes[size].get(prefix)
        if f:
            return f(data)


def _parse_bech32(parser, metadata):
    r = metadata.get("as_bech32")
    if not r:
        return
    hrp, data = r
    f = parser.bech32_prefixes().get(hrp)
    if f:
        return f(hrp, data)


def _parse_as_colon(parser, metadata):
    r = metadata.get("as_colon")
    if not r:
        return
    hrp, data = r
    f = parser.colon_prefixes().get(hrp)
    if f:
        return f(hrp, data)


def _parse_as_text(parser, metadata):
    return parser.parse_as_text(metadata.get("as_text"))


def parse_to_info(metadata, parsers):
    # TODO: simplify, and put the "type" field into info here

    for parser in parsers:
        for f in [_parse_base58, _parse_bech32, _parse_as_colon, _parse_as_text]:
            v = f(parser, metadata)
            if v:
                return v


def parse(item, parsers, metadata=None):
    if metadata is None:
        metadata = metadata_for_text(item)
    info = parse_to_info(metadata, parsers)
    if info:
        return info.get("create_f")()


def make_base58_prefixes(prefix_f_list):
    d = {}
    for prefix, f in prefix_f_list:
        size = len(prefix)
        if size not in d:
            d[size] = {}
        d[size][prefix] = f
    return d


class Parser(object):

    TYPE = None

    _base58_prefixes = make_base58_prefixes([])
    _bech32_prefixes = dict()
    _colon_prefixes = dict()

    def base58_prefixes(self):
        return self._base58_prefixes

    def bech32_prefixes(self):
        return self._bech32_prefixes

    def colon_prefixes(self):
        return self._colon_prefixes

    def parse_as_text(self, text):
        return None
