"""
Provide the following functions:

bytes_to_ints(bytes):
    yield an iterator of ints. Designed to deal with how
    Python 2 treats bytes[0] as a string while
    Python 3 treats bytes[0] as an int.

bytes_from_int(an_int):
    convert a small integer (< 256) into bytes (of length 1)

byte_to_int(one_byte):
    turn one byte into an int

bytes_from_ints(list_of_small_ints):
    return a bytes object from a list of small (< 256) integers

to_bytes(v, length, byteorder):
    convert integer v into a bytes object

from_bytes(bytes, byteorder, *, signed=False):
    convert the bytes object into an integer

The last two functions are designed to mimic the methods of the same
name that exist on int in Python 3 only. For Python 3, it uses
those implementations.
"""

bytes_to_ints = (lambda x: [ord(c) for c in x]) if bytes == str else lambda x: x
bytes_from_int = chr if bytes == str else lambda x: bytes([x])
byte_to_int = ord if bytes == str else lambda x: x
bytes_from_ints = (lambda l: b''.join(chr(x) for x in l)) if bytes == str else bytes


if hasattr(int, "to_bytes"):
    to_bytes = lambda v, length, byteorder="big": v.to_bytes(length, byteorder=byteorder)
    from_bytes = lambda bytes, byteorder="big", signed=False: int.from_bytes(
        bytes, byteorder=byteorder, signed=signed)
    int_to_bytes = lambda v: v.to_bytes((v.bit_length()+7)//8, byteorder="big")
    int_from_bytes = lambda v: int.from_bytes(v, byteorder="big")
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
        if signed and byte_to_int(bytes[0]) & 0x80:
            v = v - (1 << (8*len(bytes)))
        return v

    def int_to_bytes(v):
        l = bytearray()
        while v > 0:
            l.append(v & 0xff)
            v >>= 8
        l.reverse()
        return bytes(l)

    def int_from_bytes(s):
        v = 0
        for c in bytes_to_ints(s):
            v <<= 8
            v += c
        return v
