from .exceptions import EncodingError


def to_long(base, lookup_f, s):
    """
    Convert an array to a (possibly bignum) integer, along with a prefix value
    of how many prefixed zeros there are.

    base:
        the source base
    lookup_f:
        a function to convert an element of s to a value between 0 and base-1.
    s:
        the value to convert
    """
    prefix = 0
    v = 0
    for c in s:
        v *= base
        try:
            v += lookup_f(c)
        except Exception:
            raise EncodingError("bad character %s in string %s" % (c, s))
        if v == 0:
            prefix += 1
    return v, prefix


def from_long(v, prefix, base, charset):
    """The inverse of to_long. Convert an integer to an arbitrary base.

    v: the integer value to convert
    prefix: the number of prefixed 0s to include
    base: the new base
    charset: an array indicating what printable character to use for each value.
    """
    ba = bytearray()
    while v > 0:
        try:
            v, mod = divmod(v, base)
            ba.append(charset(mod))
        except Exception:
            raise EncodingError("can't convert to character corresponding to %d" % mod)
    ba.extend([charset(0)] * prefix)
    ba.reverse()
    return bytes(ba)


"""
The MIT License (MIT)

Copyright (c) 2013 by Richard Kiss

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
