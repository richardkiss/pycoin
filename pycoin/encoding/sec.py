from ..intbytes import int2byte

from .base_conversion import EncodingError
from .bytes32 import from_bytes_32, to_bytes_32
from .hash import hash160


def public_pair_to_sec(public_pair, compressed=True):
    """Convert a public pair (a pair of bignums corresponding to a public key) to the
    gross internal sec binary format used by OpenSSL."""
    x_str = to_bytes_32(public_pair[0])
    if compressed:
        return int2byte((2 + (public_pair[1] & 1))) + x_str
    y_str = to_bytes_32(public_pair[1])
    return b'\4' + x_str + y_str


def sec_to_public_pair(sec, generator=None, strict=True):
    """Convert a public key in sec binary format to a public pair."""
    byte_count = (generator.p().bit_length() + 7) >> 3 if generator else (len(sec) - 1)
    x = from_bytes_32(sec[1:1 + byte_count])
    sec0 = sec[:1]
    if len(sec) == 1 + byte_count * 2:
        isok = sec0 == b'\4'
        if not strict:
            isok = isok or (sec0 in [b'\6', b'\7'])
        if isok:
            y = from_bytes_32(sec[1+byte_count:1+2*byte_count])
            return (x, y)
    elif len(sec) == 1 + byte_count:
        if not strict or (sec0 in (b'\2', b'\3')):
            is_y_odd = (sec0 != b'\2')
            return generator.points_for_x(x)[is_y_odd]
    raise EncodingError("bad sec encoding for public key")


def is_sec(sec):
    c = sec[:1]
    size = len(sec)
    if c in (b'\2', b'\3') and size == 33:
        return True
    return c == b'\4' and size == 65


def is_sec_compressed(sec):
    """Return a boolean indicating if the sec represents a compressed public key."""
    return sec[:1] in (b'\2', b'\3')


def public_pair_to_hash160_sec(public_pair, compressed=True):
    """Convert a public_pair (corresponding to a public key) to hash160_sec format.
    This is a hash of the sec representation of a public key, and is used to generate
    the corresponding Bitcoin address."""
    return hash160(public_pair_to_sec(public_pair, compressed=compressed))


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
