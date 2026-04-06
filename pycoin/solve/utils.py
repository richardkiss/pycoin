from __future__ import annotations

import hashlib
from typing import Any, Iterable

from pycoin.encoding.hash import hash160
from pycoin.encoding.sec import public_pair_to_hash160_sec


def build_hash160_lookup(
    secret_exponents: Iterable[int], generators: Iterable[Any]
) -> dict[bytes, tuple[int, Any, bool, Any]]:
    d: dict[bytes, tuple[int, Any, bool, Any]] = {}
    for secret_exponent in secret_exponents:
        for generator in generators:
            public_pair = secret_exponent * generator
            for compressed in (True, False):
                h160 = public_pair_to_hash160_sec(public_pair, compressed=compressed)
                d[h160] = (secret_exponent, public_pair, compressed, generator)
    return d


def build_p2sh_lookup(scripts: Iterable[bytes]) -> dict[bytes, bytes]:
    scripts_list = list(scripts)
    d1: dict[bytes, bytes] = dict((hash160(s), s) for s in scripts_list)
    d1.update((hashlib.sha256(s).digest(), s) for s in scripts_list)
    return d1


def build_sec_lookup(sec_values: Iterable[bytes] | None) -> dict[bytes, bytes]:
    d: dict[bytes, bytes] = {}
    for sec in sec_values or []:
        d[hash160(sec)] = sec
    return d
