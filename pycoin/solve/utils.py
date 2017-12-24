import hashlib

from pycoin.encoding.hash import hash160
from pycoin.encoding.sec import public_pair_to_hash160_sec


def build_hash160_lookup(secret_exponents, generators):
    d = {}
    for secret_exponent in secret_exponents:
        for generator in generators:
            public_pair = secret_exponent * generator
            for compressed in (True, False):
                hash160 = public_pair_to_hash160_sec(public_pair, compressed=compressed)
                d[hash160] = (secret_exponent, public_pair, compressed, generator)
    return d


def build_p2sh_lookup(scripts):
    d1 = dict((hash160(s), s) for s in scripts)
    d1.update((hashlib.sha256(s).digest(), s) for s in scripts)
    return d1


def build_sec_lookup(sec_values):
    d = {}
    for sec in sec_values or []:
        d[hash160(sec)] = sec
    return d
