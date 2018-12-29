from pycoin.networks.ParseAPI import ParseAPI
from pycoin.networks.parseable_str import parseable_str, parse_b58

from .hash import groestlHash


def b58_groestl(s):
    data = parse_b58(s)
    if data:
        data, the_hash = data[:-4], data[-4:]
        if groestlHash(data)[:4] == the_hash:
            return data


def parse_b58_groestl(s):
    s = parseable_str(s)
    return s.cache("b58_groestl", b58_groestl)


class GRSParseAPI(ParseAPI):
    """Set GRS parse functions."""

    def parse_b58_hashed(self, s):
        return parse_b58_groestl(s)
