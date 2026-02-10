"""
Provide the following functions for byte operations in Python 3:

iterbytes(buf):
    return an iterator of ints corresponding to the bytes of buf

indexbytes(buf, i):
    return the int for the ith byte of buf

int2byte(an_int):
    convert a small integer (< 256) into bytes (with length 1)

byte2int(bs):
    turn bs[0] into an int (0-255)
"""

import operator
import struct

# Python 3 implementations
iterbytes = iter
indexbytes = operator.getitem
int2byte = struct.Struct(">B").pack
byte2int = operator.itemgetter(0)
