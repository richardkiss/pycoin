import hashlib

import groestlcoin_hash

from pycoin.encoding.hexbytes import bytes_as_revhex


def sha256(data):
    return bytes_as_revhex(hashlib.sha256(data).digest())


def groestlHash(data):
    """Groestl-512 compound hash."""
    return bytes_as_revhex(groestlcoin_hash.getHash(data, len(data)))
