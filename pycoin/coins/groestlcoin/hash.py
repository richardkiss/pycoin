from __future__ import annotations

import hashlib

from pycoin.encoding.hexbytes import bytes_as_revhex


def sha256(data: bytes) -> bytes:
    return bytes_as_revhex(hashlib.sha256(data).digest())


def groestlHash(data: bytes) -> bytes:
    """Groestl-512 compound hash."""
    try:
        import groestlcoin_hash
    except ImportError:
        t = 'Groestlcoin requires the groestlcoin_hash package ("pip install groestlcoin_hash").'
        print(t)
        raise ImportError(t)

    return bytes_as_revhex(groestlcoin_hash.getHash(data, len(data)))
