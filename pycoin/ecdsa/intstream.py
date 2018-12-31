
from pycoin.intbytes import iterbytes, byte2int


def _to_bytes(v, length, byteorder="big"):
    """This is the same functionality as ``int.to_bytes`` in python 3"""
    return v.to_bytes(length, byteorder=byteorder)


def _from_bytes(bytes, byteorder="big", signed=False):
    """This is the same functionality as ``int.from_bytes`` in python 3"""
    return int.from_bytes(bytes, byteorder=byteorder, signed=signed)


if hasattr(int, "to_bytes"):
    to_bytes = _to_bytes
    from_bytes = _from_bytes
else:
    def to_bytes(v, length, byteorder="big"):
        """This is the same functionality as ``int.to_bytes`` in python 3"""
        ba = bytearray()
        for i in range(length):
            mod = v & 0xff
            v >>= 8
            ba.append(mod)
        if byteorder == "big":
            ba.reverse()
        return bytes(ba)

    def from_bytes(bytes, byteorder="big", signed=False):
        """This is the same functionality as ``int.from_bytes`` in python 3"""
        if byteorder != "big":
            bytes = reversed(bytes)
        v = 0
        for c in iterbytes(bytes):
            v <<= 8
            v += c
        if signed and byte2int(bytes) & 0x80:
            v = v - (1 << (8*len(bytes)))
        return v
