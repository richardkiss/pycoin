import hashlib
import hmac

from . import intstream


if hasattr(1, "bit_length"):
    def bit_length(v):
        "the ``int.bit_length`` in `python 3 <https://docs.python.org/3/library/stdtypes.html#int.bit_length>`_"
        return v.bit_length()
else:
    def bit_length(self):
        "the ``int.bit_length`` in `python 3 <https://docs.python.org/3/library/stdtypes.html#int.bit_length>`_"
        # compared to "while n>0: bl +=1 ; n >>= 1", this is much faster in both python2 and pypy
        # code taken from the link above
        s = bin(self)  # binary representation:  bin(-37) --> '-0b100101'
        s = s.lstrip('-0b')  # remove leading zeros and minus sign
        return len(s)  # len('100101') --> 6


def deterministic_generate_k(generator_order, secret_exponent, val, hash_f=hashlib.sha256):
    """
    :param generator_order: result from `pycoin.ecdsa.Generator.Generator.order`,
        necessary to ensure the k value is within bound
    :param secret_exponent: an integer secret_exponent to generate the k value for
    :param val: the value to be signed, also used as an entropy source for the k value
    :returns: an integer k such that ``1 <= k < generator_order``, complying with
        <https://tools.ietf.org/html/rfc6979>
    """
    n = generator_order
    bln = bit_length(n)
    order_size = (bln + 7) // 8
    hash_size = hash_f().digest_size
    v = b'\x01' * hash_size
    k = b'\x00' * hash_size
    priv = intstream.to_bytes(secret_exponent, length=order_size)
    shift = 8 * hash_size - bln
    if shift > 0:
        val >>= shift
    if val >= n:
        val -= n
    h1 = intstream.to_bytes(val, length=order_size)
    k = hmac.new(k, v + b'\x00' + priv + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()
    k = hmac.new(k, v + b'\x01' + priv + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()

    while 1:
        t = bytearray()

        while len(t) < order_size:
            v = hmac.new(k, v, hash_f).digest()
            t.extend(v)

        k1 = intstream.from_bytes(bytes(t))

        k1 >>= (len(t)*8 - bln)
        if k1 >= 1 and k1 < n:
            return k1

        k = hmac.new(k, v + b'\x00', hash_f).digest()
        v = hmac.new(k, v, hash_f).digest()


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
