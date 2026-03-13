"""
Provide utility functions for working with bytes:

iterbytes(buf):
    return an iterator of ints corresponding to the bytes of buf

indexbytes(buf, i):
    return the int for the ith byte of buf

int2byte(an_int):
    convert a small integer (< 256) into bytes (with length 1)

byte2int(bs):
    turn bs[0] into an int (0-255)
"""

import struct
from typing import Iterator


def iterbytes(buf: bytes) -> Iterator[int]:
    """Return an iterator of ints corresponding to the bytes of buf."""
    return iter(buf)


def indexbytes(buf: bytes, i: int) -> int:
    """Return the int for the ith byte of buf."""
    return buf[i]


def int2byte(an_int: int) -> bytes:
    """Convert a small integer (< 256) into bytes (with length 1)."""
    return struct.Struct(">B").pack(an_int)


def byte2int(bs: bytes) -> int:
    """Turn bs[0] into an int (0-255)."""
    return bs[0]
