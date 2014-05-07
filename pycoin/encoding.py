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

import hashlib

bytes_from_int = chr if bytes == str else lambda x: bytes([x])
byte_to_int = ord if bytes == str else lambda x: x

BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_BASE = len(BASE58_ALPHABET)
BASE58_LOOKUP = dict((c, i) for i, c in enumerate(BASE58_ALPHABET))


class EncodingError(Exception):
    pass


def ripemd160(data):
    return hashlib.new("ripemd160", data)

try:
    ripemd160(b'').digest()
except Exception:
    # stupid Google App Engine hashlib doesn't support ripemd160 for some stupid reason
    # import it from pycrypto. You need to add
    # - name: pycrypto
    #   version: "latest"
    # to the "libraries" section of your app.yaml
    from Crypto.Hash.RIPEMD import RIPEMD160Hash as ripemd160


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
    l = bytearray()
    while v > 0:
        try:
            v, mod = divmod(v, base)
            l.append(charset(mod))
        except Exception:
            raise EncodingError("can't convert to character corresponding to %d" % mod)
    l.extend([charset(0)] * prefix)
    l.reverse()
    return bytes(l)


def to_bytes_32(v):
    v = from_long(v, 0, 256, lambda x: x)
    if len(v) > 32:
        raise ValueError("input to to_bytes_32 is too large")
    return ((b'\0' * 32) + v)[-32:]

if hasattr(int, "to_bytes"):
    to_bytes_32 = lambda v: v.to_bytes(32, byteorder="big")


def from_bytes_32(v):
    if len(v) != 32:
        raise ValueError("input to from_bytes_32 is wrong length")
    return to_long(256, byte_to_int, v)[0]

if hasattr(int, "from_bytes"):
    from_bytes_32 = lambda v: int.from_bytes(v, byteorder="big")


def double_sha256(data):
    """A standard compound hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data):
    """A standard compound hash."""
    return ripemd160(hashlib.sha256(data).digest()).digest()


def b2a_base58(s):
    """Convert binary to base58 using BASE58_ALPHABET. Like Bitcoin addresses."""
    v, prefix = to_long(256, byte_to_int, s)
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


def is_hashed_base58_valid(base58):
    """Return True if and only if base58 is valid hashed_base58."""
    try:
        a2b_hashed_base58(base58)
    except EncodingError:
        return False
    return True


def wif_to_tuple_of_prefix_secret_exponent_compressed(wif):
    """
    Return a tuple of (prefix, secret_exponent, is_compressed).
    """
    decoded = a2b_hashed_base58(wif)
    actual_prefix, private_key = decoded[:1], decoded[1:]
    compressed = len(private_key) > 32
    return actual_prefix, from_bytes_32(private_key[:32]), compressed


def wif_to_tuple_of_secret_exponent_compressed(wif, allowable_wif_prefixes=[b'\x80']):
    """Convert a WIF string to the corresponding secret exponent. Private key manipulation.
    Returns a tuple: the secret exponent, as a bignum integer, and a boolean indicating if the
    WIF corresponded to a compressed key or not.

    Not that it matters, since we can use the secret exponent to generate both the compressed
    and uncompressed Bitcoin address."""
    actual_prefix, secret_exponent, is_compressed = wif_to_tuple_of_prefix_secret_exponent_compressed(wif)
    if actual_prefix not in allowable_wif_prefixes:
        raise EncodingError("unexpected first byte of WIF %s" % wif)
    return secret_exponent, is_compressed


def wif_to_secret_exponent(wif, allowable_wif_prefixes=[b'\x80']):
    """Convert a WIF string to the corresponding secret exponent."""
    return wif_to_tuple_of_secret_exponent_compressed(wif, allowable_wif_prefixes=allowable_wif_prefixes)[0]


def is_valid_wif(wif, allowable_wif_prefixes=[b'\x80']):
    """Return a boolean indicating if the WIF is valid."""
    try:
        wif_to_secret_exponent(wif, allowable_wif_prefixes=allowable_wif_prefixes)
    except EncodingError:
        return False
    return True


def secret_exponent_to_wif(secret_exp, compressed=True, wif_prefix=b'\x80'):
    """Convert a secret exponent (correspdong to a private key) to WIF format."""
    d = wif_prefix + to_bytes_32(secret_exp)
    if compressed:
        d += b'\01'
    return b2a_hashed_base58(d)


def public_pair_to_sec(public_pair, compressed=True):
    """Convert a public pair (a pair of bignums corresponding to a public key) to the
    gross internal sec binary format used by OpenSSL."""
    x_str = to_bytes_32(public_pair[0])
    if compressed:
        return bytes_from_int((2 + (public_pair[1] & 1))) + x_str
    y_str = to_bytes_32(public_pair[1])
    return b'\4' + x_str + y_str


def sec_to_public_pair(sec):
    """Convert a public key in sec binary format to a public pair."""
    x = from_bytes_32(sec[1:33])
    sec0 = sec[:1]
    if sec0 == b'\4':
        y = from_bytes_32(sec[33:65])
        from .ecdsa import generator_secp256k1, is_public_pair_valid
        public_pair = (x, y)
        # verify this is on the curve
        if not is_public_pair_valid(generator_secp256k1, public_pair):
            raise EncodingError("invalid (x, y) pair")
        return public_pair
    if sec0 in (b'\2', b'\3'):
        from .ecdsa import public_pair_for_x, generator_secp256k1
        return public_pair_for_x(generator_secp256k1, x, is_even=(sec0 == b'\2'))
    raise EncodingError("bad sec encoding for public key")


def is_sec_compressed(sec):
    """Return a boolean indicating if the sec represents a compressed public key."""
    return sec[:1] in (b'\2', b'\3')


def public_pair_to_hash160_sec(public_pair, compressed=True):
    """Convert a public_pair (corresponding to a public key) to hash160_sec format.
    This is a hash of the sec representation of a public key, and is used to generate
    the corresponding Bitcoin address."""
    return hash160(public_pair_to_sec(public_pair, compressed=compressed))


def hash160_sec_to_bitcoin_address(hash160_sec, address_prefix=b'\0'):
    """Convert the hash160 of a sec version of a public_pair to a Bitcoin address."""
    return b2a_hashed_base58(address_prefix + hash160_sec)


def bitcoin_address_to_hash160_sec_with_prefix(bitcoin_address):
    """
    Convert a Bitcoin address back to the hash160_sec format and
    also return the prefix.
    """
    blob = a2b_hashed_base58(bitcoin_address)
    if len(blob) != 21:
        raise EncodingError("incorrect binary length (%d) for Bitcoin address %s" %
                            (len(blob), bitcoin_address))
    if blob[:1] not in [b'\x6f', b'\0']:
        raise EncodingError("incorrect first byte (%s) for Bitcoin address %s" % (blob[0], bitcoin_address))
    return blob[1:], blob[:1]


def bitcoin_address_to_hash160_sec(bitcoin_address, address_prefix=b'\0'):
    """Convert a Bitcoin address back to the hash160_sec format of the public key.
    Since we only know the hash of the public key, we can't get the full public key back."""
    hash160, actual_prefix = bitcoin_address_to_hash160_sec_with_prefix(bitcoin_address)
    if (address_prefix == actual_prefix):
        return hash160
    raise EncodingError("Bitcoin address %s for wrong network" % bitcoin_address)


def public_pair_to_bitcoin_address(public_pair, compressed=True, address_prefix=b'\0'):
    """Convert a public_pair (corresponding to a public key) to a Bitcoin address."""
    return hash160_sec_to_bitcoin_address(public_pair_to_hash160_sec(
        public_pair, compressed=compressed), address_prefix=address_prefix)


def is_valid_bitcoin_address(bitcoin_address, allowable_prefixes=b'\0'):
    """Return True if and only if bitcoin_address is valid."""
    try:
        hash160, prefix = bitcoin_address_to_hash160_sec_with_prefix(bitcoin_address)
    except EncodingError:
        return False
    return prefix in allowable_prefixes
