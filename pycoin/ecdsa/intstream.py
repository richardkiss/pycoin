
from pycoin.intbytes import iterbytes, byte2int


def _to_bytes(v, length, byteorder="big"):
    return v.to_bytes(length, byteorder=byteorder)


def _from_bytes(bytes, byteorder="big", signed=False):
    return int.from_bytes(bytes, byteorder=byteorder, signed=signed)


if hasattr(int, "to_bytes"):
    to_bytes = _to_bytes
    from_bytes = _from_bytes
else:
    def to_bytes(v, length, byteorder="big"):
        l = bytearray()
        for i in range(length):
            mod = v & 0xff
            v >>= 8
            l.append(mod)
        if byteorder == "big":
            l.reverse()
        return bytes(l)

    def from_bytes(bytes, byteorder="big", signed=False):
        if byteorder != "big":
            bytes = reversed(bytes)
        v = 0
        for c in iterbytes(bytes):
            v <<= 8
            v += c
        if signed and byte2int(bytes) & 0x80:
            v = v - (1 << (8*len(bytes)))
        return v
