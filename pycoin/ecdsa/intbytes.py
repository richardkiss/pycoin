"""
Provide the following functions:

bytes_to_ints(bytes):
    yield an iterator of ints. Designed to deal with how
    Python 2 treats bytes[0] as a string while
    Python 3 treats bytes[0] as an int.

to_bytes(v, length, byteorder):
    convert integer v into a bytes object

from_bytes(bytes, byteorder, *, signed=False):
    convert the bytes object into an integer

The last two functions are designed to mimic the methods of the same
name that exist on int in Python 3 only. For Python 3, use
those implementations.
"""

bytes_to_ints = (lambda x: (ord(c) for c in x)) if bytes == str else lambda x: x

if hasattr(int, "to_bytes"):
    to_bytes = lambda v, length, byteorder="big": v.to_bytes(length, byteorder=byteorder)
    from_bytes = lambda bytes, byteorder="big", signed=False: int.from_bytes(bytes, byteorder="big", signed=signed)
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
        for c in bytes_to_ints(bytes):
            v <<= 8
            v += c
        if signed and bytes[0] & 0x80:
            v = v - (1<<(8*len(bytes)))
        return v
