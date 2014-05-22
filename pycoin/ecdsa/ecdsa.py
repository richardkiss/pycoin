
"""
Some portions adapted from https://github.com/warner/python-ecdsa/ Copyright (c) 2010 Brian Warner
who granted its use under this license:

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.


Portions written in 2005 by Peter Pearson and placed in the public domain.
"""

import hashlib
import hmac

from . import ellipticcurve, intbytes, numbertheory


if hasattr(1, "bit_length"):
    bit_length = lambda v: v.bit_length()
else:
    def bit_length(self):
        # Make this library compatible with python < 2.7
        # https://docs.python.org/3.5/library/stdtypes.html#int.bit_length
        s = bin(self)  # binary representation:  bin(-37) --> '-0b100101'
        s = s.lstrip('-0b')  # remove leading zeros and minus sign
        return len(s)  # len('100101') --> 6


def deterministic_generate_k(generator_order, secret_exponent, val, hash_f=hashlib.sha256):
    """
    Generate K value according to https://tools.ietf.org/html/rfc6979
    """
    n = generator_order
    order_size = (bit_length(n) + 7) // 8
    hash_size = hash_f().digest_size
    v = b'\x01' * hash_size
    k = b'\x00' * hash_size
    priv = intbytes.to_bytes(secret_exponent, length=order_size)
    shift = 8 * hash_size - bit_length(n)
    if shift > 0:
        val >>= shift
    if val > n:
        val -= n
    h1 = intbytes.to_bytes(val, length=order_size)
    k = hmac.new(k, v + b'\x00' + priv + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()
    k = hmac.new(k, v + b'\x01' + priv + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()

    while 1:
        t = bytearray()

        while len(t) < order_size:
            v = hmac.new(k, v, hash_f).digest()
            t.extend(v)

        k1 = intbytes.from_bytes(bytes(t))

        k1 >>= (len(t)*8 - bit_length(n))
        if k1 >= 1 and k1 < n:
            return k1

        k = hmac.new(k, v + b'\x00', hash_f).digest()
        v = hmac.new(k, v, hash_f).digest()


def sign(generator, secret_exponent, val):
    """Return a signature for the provided hash, using the provided
    random nonce.  It is absolutely vital that random_k be an unpredictable
    number in the range [1, self.public_key.point.order()-1].  If
    an attacker can guess random_k, he can compute our private key from a
    single signature.  Also, if an attacker knows a few high-order
    bits (or a few low-order bits) of random_k, he can compute our private
    key from many signatures.  The generation of nonces with adequate
    cryptographic strength is very difficult and far beyond the scope
    of this comment.

    May raise RuntimeError, in which case retrying with a new
    random value k is in order.
    """
    G = generator
    n = G.order()
    k = deterministic_generate_k(n, secret_exponent, val)
    p1 = k * G
    r = p1.x()
    if r == 0: raise RuntimeError("amazingly unlucky random number r")
    s = ( numbertheory.inverse_mod( k, n ) * \
          ( val + ( secret_exponent * r ) % n ) ) % n
    if s == 0: raise RuntimeError("amazingly unlucky random number s")
    return (r, s)

def public_pair_for_secret_exponent(generator, secret_exponent):
    return (generator*secret_exponent).pair()

def public_pair_for_x(generator, x, is_even):
    curve = generator.curve()
    p = curve.p()
    alpha = ( pow(x, 3, p)  + curve.a() * x + curve.b() ) % p
    beta = numbertheory.modular_sqrt(alpha, p)
    if is_even == bool(beta & 1):
        return (x, p - beta)
    return (x, beta)

def is_public_pair_valid(generator, public_pair):
    return generator.curve().contains_point(public_pair[0], public_pair[1])

def verify(generator, public_pair, val, signature):
    """
    Verify that signature is a valid signature of hash.
    Return True if the signature is valid.
    """

    # From X9.62 J.3.1.

    G = generator
    n = G.order()
    r, s = signature
    if r < 1 or r > n-1: return False
    if s < 1 or s > n-1: return False
    c = numbertheory.inverse_mod( s, n )
    u1 = ( val * c ) % n
    u2 = ( r * c ) % n
    point = u1 * G + u2 * ellipticcurve.Point( G.curve(), public_pair[0], public_pair[1], G.order() )
    v = point.x() % n
    return v == r

def possible_public_pairs_for_signature(generator, value, signature):
    """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
    G = generator
    curve = G.curve()
    order = G.order()
    p = curve.p()

    r,s = signature

    possible_points = set()

    #recid = nV - 27
    # 1.1
    inv_r = numbertheory.inverse_mod(r,order)
    minus_e = -value % order
    x = r
    # 1.3
    alpha = ( pow(x,3,p)  + curve.a() * x + curve.b() ) % p
    beta = numbertheory.modular_sqrt(alpha, p)
    for y in [beta, p - beta]:
        # 1.4 the constructor checks that nR is at infinity
        R = ellipticcurve.Point(curve, x, y, order)
        # 1.6 compute Q = r^-1 (sR - eG)
        Q = inv_r * ( s * R + minus_e * G )
        public_pair = (Q.x(), Q.y())
        # check that Q is the public key
        if verify(generator, public_pair, value, signature):
        # check that we get the original signing address
            possible_points.add(public_pair)
    return possible_points
