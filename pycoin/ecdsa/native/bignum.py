"""
Arrange to access a shared-object version of the bignum library using Python ctypes.
"""

import ctypes
import ctypes.util
import struct
from typing import Any, Generator, Iterator

from ..intstream import to_bytes


def bignum_type_for_library(library: Any) -> type[Any]:
    ULONG_FACTOR = 1 << (8 * ctypes.sizeof(ctypes.c_ulong))

    class BignumType(ctypes.Structure):
        """
        The structure that's manipulated by bn, the bignum library.
        struct bignum_st {
            BN_ULONG *d;    /* Pointer to an array of 'BN_BITS2' bit chunks. */
            int top;    /* Index of last used d +1. */
            /* The next are internal book keeping for bn_expand. */
            int dmax;    /* Size of the d array. */
            int neg;    /* one if the number is negative */
            int flags;
        };
        """

        _fields_ = [
            ("d", ctypes.POINTER(ctypes.c_ulong)),
            ("top", ctypes.c_int),
            ("dmax", ctypes.c_int),
            ("neg", ctypes.c_int),
            ("flags", ctypes.c_int),
        ]

        def __init__(self, n: int = 0) -> None:
            "Create a BignumType from an int"
            negative = n < 0
            if negative:
                n = -n
            the_len = (n.bit_length() + 7) // 8
            sign = b"\x80" if negative else b"\0"
            the_bytes = (
                struct.pack(">L", the_len + 1) + sign + to_bytes(n, the_len, "big")
            )
            library.BN_mpi2bn(the_bytes, the_len + 5, self)

        def __del__(self) -> None:
            "Release memory used by native library"
            library.BN_clear_free(self)

        def __int__(self) -> int:
            "cast to int"
            return self.to_int()

        def to_int(self) -> int:
            "Return this bignum's value as a Python integer."
            value, factor = 0, 1
            for w in self.datawords():
                value += w * factor
                factor *= ULONG_FACTOR
            if self.neg:
                value = -value
            return value

        def datawords(self) -> Generator[Any, None, None]:
            "Yield the words in the little-endian data array."
            return (int(self.d[k]) for k in range(self.top))

        def __repr__(self) -> str:
            return "BignumType(%d)" % self.to_int()

    return BignumType
