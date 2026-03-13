import binascii
from typing import Union


def h2b(h: str) -> bytes:
    """
    A version of binascii.unhexlify that accepts unicode strings.

    Raises a ValueError on failure (unlike binascii.unhexlify, which
    raises a TypeError or binascii.Error in some cases).
    """
    try:
        return binascii.unhexlify(h.encode("ascii"))
    except Exception:
        raise ValueError("h2b failed on %s" % h)


def h2b_rev(h: str) -> bytes:
    return h2b(h)[::-1]


def b2h(the_bytes: bytes) -> str:
    return binascii.hexlify(the_bytes).decode("utf8")


def b2h_rev(the_bytes: bytes) -> str:
    return b2h(bytearray(reversed(the_bytes)))


class bytes_as_revhex(bytes):
    def __str__(self) -> str:
        return b2h_rev(self)

    def __repr__(self) -> str:
        return b2h_rev(self)


class bytes_as_hex(bytes):
    def __str__(self) -> str:
        return b2h(self)

    def __repr__(self) -> str:
        return b2h(self)
