from pycoin.coins.SolutionChecker import ScriptError

from . import errno


class IntStreamer(object):

    @classmethod
    def int_from_script_bytes(class_, s, require_minimal=False):
        if len(s) == 0:
            return 0
        s = bytearray(s)
        s.reverse()
        i = s[0]
        v = i & 0x7f
        if require_minimal:
            if v == 0:
                if len(s) <= 1 or ((s[1] & 0x80) == 0):
                    raise ScriptError("non-minimally encoded", errno.UNKNOWN_ERROR)
        is_negative = ((i & 0x80) > 0)
        for b in s[1:]:
            v <<= 8
            v += b
        if is_negative:
            v = -v
        return v

    @classmethod
    def int_to_script_bytes(class_, v):
        if v == 0:
            return b''
        is_negative = (v < 0)
        if is_negative:
            v = -v
        ba = bytearray()
        while v >= 256:
            ba.append(v & 0xff)
            v >>= 8
        ba.append(v & 0xff)
        if ba[-1] >= 128:
            ba.append(0x80 if is_negative else 0)
        elif is_negative:
            ba[-1] |= 0x80
        return bytes(ba)
