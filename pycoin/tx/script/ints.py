"""
Conversion utilities for script integers.


The MIT License (MIT)

Copyright (c) 2017 by Richard Kiss

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import binascii

from . import errno
from . import ScriptError


VM_TRUE = b'\1'
VM_FALSE = b''


def bool_from_script_bytes(v, require_minimal=False):
    return bool(int_from_script_bytes(v, require_minimal=require_minimal))


def bool_to_script_bytes(v):
    return VM_TRUE if v else VM_FALSE


def int_from_script_bytes(s, require_minimal=False):
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


def nonnegative_int_from_script_bytes(b, require_minimal):
    v = int_from_script_bytes(b, require_minimal=require_minimal)
    if v < 0:
        raise ScriptError("unexpectedly got negative value", errno.INVALID_STACK_OPERATION)
    return v


def int_to_script_bytes(v):
    if v == 0:
        return b''
    is_negative = (v < 0)
    if is_negative:
        v = -v
    l = bytearray()
    while v >= 256:
        l.append(v & 0xff)
        v >>= 8
    l.append(v & 0xff)
    if l[-1] >= 128:
        l.append(0x80 if is_negative else 0)
    elif is_negative:
        l[-1] |= 0x80
    return bytes(l)
