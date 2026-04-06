from __future__ import annotations

from typing import Any

from pycoin.networks.ParseAPI import ParseAPI
from pycoin.networks.parseable_str import parseable_str, parse_b58

from .hash import groestlHash


def b58_groestl(s: str) -> bytes | None:
    data = parse_b58(s)
    if data:
        data, the_hash = data[:-4], data[-4:]
        if groestlHash(data)[:4] == the_hash:
            return data
    return None


def parse_b58_groestl(s: str) -> Any:
    ps = parseable_str(s)
    return ps.cache("b58_groestl", b58_groestl)


class GRSParseAPI(ParseAPI):
    """Set GRS parse functions."""

    def parse_b58_hashed(self, s: str) -> Any:
        return parse_b58_groestl(s)
