"""
Utilities to convert to and from base58.
"""

import math

from .base_conversion import from_long, to_long, EncodingError
from .hash import double_sha256
from ..intbytes import iterbytes


BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_ALPHABET_UTF = BASE58_ALPHABET.decode()
BASE58_BASE = len(BASE58_ALPHABET)
BASE58_LOOKUP = dict((c, i) for i, c in enumerate(BASE58_ALPHABET))

LOG_58_BASE_2 = math.log(58, 2)

POWERS_OF_58 = [pow(58, n) for n in range(math.ceil(256 / LOG_58_BASE_2))]


def b2a_base58_py2(s):
    """Convert binary to base58 using BASE58_ALPHABET. Like Bitcoin addresses."""
    v, prefix = to_long(256, lambda x: x, iterbytes(s))
    s = from_long(v, prefix, BASE58_BASE, lambda v: BASE58_ALPHABET[v])
    return s.decode("utf8")


def b2a_base58_py3(s):
    """Convert binary to base58 using BASE58_ALPHABET. Like Bitcoin addresses."""
    global POWERS_OF_58
    text = []
    s = memoryview(s)

    zero_index = 0
    while zero_index < len(s) and s[zero_index] == 0:
        text.append(BASE58_ALPHABET_UTF[0])
        zero_index += 1

    s = s[zero_index:]

    as_int = int.from_bytes(s, byteorder="big", signed=False)
    bit_length = len(s) << 3

    # find the best index
    index = math.floor(bit_length / LOG_58_BASE_2)

    while len(POWERS_OF_58) <= index:
        POWERS_OF_58.append(POWERS_OF_58[-1] * 58)

    while POWERS_OF_58[index] > as_int:
        index -= 1

    while index >= 0:
        q, r = divmod(as_int, POWERS_OF_58[index])
        text.append(BASE58_ALPHABET_UTF[q])
        as_int = r
        index -= 1
    s = ''.join(text)
    return s


b2a_base58 = b2a_base58_py3 if hasattr(int, "from_bytes") else b2a_base58_py2

def b2a_base58_test(s):
    """Convert binary to base58 using BASE58_ALPHABET. Like Bitcoin addresses."""
    r1 = b2a_base58_slow(s)
    return r1
    r2 = b2a_base58_fast(s)
    return r2
    if r1 != r2:
        breakpoint()
    assert r1 == r2
    return r1


def a2b_base58(s):
    """Convert base58 to binary using BASE58_ALPHABET."""
    v, prefix = to_long(BASE58_BASE, lambda c: BASE58_LOOKUP[c], s.encode("utf8"))
    return from_long(v, prefix, 256, lambda x: x)


def b2a_hashed_base58(data):
    """
    A "hashed_base58" structure is a base58 integer (which looks like a string)
    with four bytes of hash data at the end. Bitcoin does this in several places,
    including Bitcoin addresses.

    This function turns data (of type "bytes") into its hashed_base58 equivalent.
    """
    return b2a_base58(data + double_sha256(data)[:4])


def a2b_hashed_base58(s):
    """
    If the passed string is hashed_base58, return the binary data.
    Otherwise raises an EncodingError.
    """
    data = a2b_base58(s)
    data, the_hash = data[:-4], data[-4:]
    if double_sha256(data)[:4] == the_hash:
        return data
    raise EncodingError("hashed base58 has bad checksum %s" % s)


def is_hashed_base58_valid(base58):
    """Return True if and only if base58 is valid hashed_base58."""
    try:
        a2b_hashed_base58(base58)
    except EncodingError:
        return False
    return True


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
