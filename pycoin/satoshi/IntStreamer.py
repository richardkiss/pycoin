from __future__ import annotations

from pycoin.coins.SolutionChecker import ScriptError

from . import errno


class IntStreamer(object):
    @classmethod
    def int_from_script_bytes(class_, s: bytes, require_minimal: bool = False) -> int:
        if len(s) == 0:
            return 0
        ba = bytearray(s)
        ba.reverse()
        i = ba[0]
        v = i & 0x7F
        if require_minimal:
            if v == 0:
                if len(ba) <= 1 or ((ba[1] & 0x80) == 0):
                    raise ScriptError("non-minimally encoded", errno.UNKNOWN_ERROR)
        is_negative = (i & 0x80) > 0
        for b in ba[1:]:
            v <<= 8
            v += b
        if is_negative:
            v = -v
        return v

    @classmethod
    def int_to_script_bytes(class_, v: int) -> bytes:
        if v == 0:
            return b""
        is_negative = v < 0
        if is_negative:
            v = -v
        ba = bytearray()
        while v >= 256:
            ba.append(v & 0xFF)
            v >>= 8
        ba.append(v & 0xFF)
        if ba[-1] >= 128:
            ba.append(0x80 if is_negative else 0)
        elif is_negative:
            ba[-1] |= 0x80
        return bytes(ba)
