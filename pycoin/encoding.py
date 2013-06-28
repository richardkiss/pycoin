# -*- coding: utf-8 -*-
"""
Various utilities useful for converting one Bitcoin format to another, including some
the human-transcribable format hashed_base58.


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

import binascii
import hashlib

BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_BASE = len(BASE58_ALPHABET)
BASE58_LOOKUP = dict((c, i) for i, c in enumerate(BASE58_ALPHABET))

class EncodingError(Exception): pass

def to_long(base, lookup_f, s):
    """Convert an array to a (possibly bignum) integer, along with a prefix value of how many prefixed zeros there are.

    base: the source base
    lookup_f: a function to convert an element of s to a value between 0 and base-1.
    s: the value to convert
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
    l = []
    while v > 0:
        try:
            v, mod = divmod(v, base)
            l.append(charset(mod))
        except Exception:
            raise EncodingError("can't convert to character corresponding to %d" % mod)
    l += [charset(0)] * prefix
    l.reverse()
    return bytes(l)

def b2a_base58(s):
    """Convert binary to base58 using BASE58_ALPHABET. Like Bitcoin addresses."""
    v, prefix = to_long(256, lambda x: x, s)
    s = from_long(v, prefix, BASE58_BASE, lambda v: BASE58_ALPHABET[v])
    return s.decode("utf8")

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

def double_sha256(data):
    """A standard compound hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def ripemd160_sha256(data):
    """A standard compound hash."""
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

def wif_to_tuple_of_secret_exponent_compressed(wif):
    """Convert a WIF string to the corresponding secret exponent. Private key manipulation.
    Returns a tuple: the secret exponent, as a bignum integer, and a boolean indicating if the
    WIF corresponded to a compressed key or not.

    Not that it matters, since we can use the secret exponent to generate both the compressed
    and uncompressed Bitcoin address."""
    decoded = a2b_hashed_base58(wif)
    header80, private_key = decoded[0], decoded[1:]
    if header80 != 128:
        raise EncodingError("unexpected first byte of WIF %s" % wif)
    compressed = len(private_key) > 32
    return int.from_bytes(private_key[:32], byteorder="big"), compressed

def wif_to_secret_exponent(wif):
    """Convert a WIF string to the corresponding secret exponent."""
    return wif_to_tuple_of_secret_exponent_compressed(wif)[0]

def is_valid_wif(wif):
    """Return a boolean indicating if the WIF is valid."""
    try:
        wif_to_secret_exponent(wif)
    except EncodingError:
        return False
    return True

def secret_exponent_to_wif(secret_exp, compressed=True):
    """Convert a secret exponent (correspdong to a private key) to WIF format."""
    d = b'\x80' + secret_exp.to_bytes(32, byteorder="big")
    if compressed: d += b'\01'
    return b2a_hashed_base58(d)

def public_pair_to_ripemd160_sha256_sec(public_pair, compressed=True):
    """Convert a public_pair (corresponding to a public key) to ripemd160_sha256_sec format.
    This is a hash of the sec representation of a public key, and is used to generate
    the corresponding Bitcoin address."""
    return ripemd160_sha256(public_pair_to_sec(public_pair, compressed=compressed))

def public_pair_to_bitcoin_address(public_pair, compressed=True):
    """Convert a public_pair (corresponding to a public key) to a Bitcoin address."""
    return b2a_hashed_base58(b"\x00" + public_pair_to_ripemd160_sha256_sec(public_pair, compressed=compressed))

def bitcoin_address_to_ripemd160_sha256_sec(bitcoin_address):
    """Convert a Bitcoin address back to the ripemd160_sha256_sec format of the public key.
    Since we only know the hash of the public key, we can't get the full public key back."""
    blob = a2b_hashed_base58(bitcoin_address)
    if len(blob) != 21:
        raise EncodingError("incorrect binary length (%d) for Bitcoin address %s" % (len(blob), bitcoin_address))
    if blob[0] != 0:
        raise EncodingError("incorrect first byte (%d) for Bitcoin address %s" % (blob[0], bitcoin_address))
    return blob[1:]

def is_valid_bitcoin_address(bitcoin_address):
    """Return True if and only if bitcoin_address is valid."""
    try:
        bitcoin_address_to_ripemd160_sha256_sec(bitcoin_address)
    except EncodingError:
        return False
    return True

def is_hashed_base58_valid(base58):
    """Return True if and only if base58 is valid hashed_base58."""
    try:
        a2b_hashed_base58(base58)
    except EncodingError:
        return False
    return True

def public_pair_to_sec(public_pair, compressed=True):
    """Convert a public pair (a pair of bignums corresponding to a public key) to the
    gross internal sec binary format used by OpenSSL."""
    x_str = public_pair[0].to_bytes(32, byteorder="big")
    if compressed:
        return bytes([(2 + (public_pair[1] & 1))]) + x_str
    y_str = public_pair[1].to_bytes(32, byteorder="big")
    return bytes([4]) + x_str + y_str

def public_pair_from_sec(sec):
    """Convert a public key in sec binary format to a public pair."""
    x = int.from_bytes(sec[1:33], byteorder="big")
    if sec[0] == 4:
        y = int.from_bytes(sec[33:65], byteorder="big")
        # TODO: verify this is on the curve
        return (x, y)
    if sec[0] in (2, 3):
        from .ecdsa import public_pair_for_x, generator_secp256k1
        return public_pair_for_x(generator_secp256k1, x, is_even=(sec[0]==2))
    raise EncodingError("bad sec encoding for public key")

def is_sec_compressed(sec):
    """Return a boolean indicating if the sec represents a compressed public key."""
    return sec[0] in (2,3)
