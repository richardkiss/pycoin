"""
Implement instructions of the Bitcoin VM.


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

from . import errno
from . import ScriptError

from ...encoding import hash160, double_sha256, ripemd160


def do_OP_NOP(s):
    pass


for i in range(1, 11):
    exec("def do_OP_NOP%d(s): pass" % i)


def do_OP_VER(stack):
    raise ScriptError("OP_VER encountered", errno.BAD_OPCODE)


def do_OP_RESERVED1(stack):
    raise ScriptError("OP_RESERVED1 encountered", errno.BAD_OPCODE)


def do_OP_RESERVED2(stack):
    raise ScriptError("OP_RESERVED2 encountered", errno.BAD_OPCODE)


def do_OP_RETURN(stack):
    raise ScriptError("OP_RETURN encountered", errno.OP_RETURN)


def do_OP_2DROP(stack):
    """
    >>> s = [1, 2, 3]
    >>> do_OP_2DROP(s)
    >>> print(s)
    [1]
    """
    stack.pop()
    stack.pop()


def do_OP_2DUP(stack):
    #  (x1 x2 -- x1 x2 x1 x2)
    """
    >>> s = [1, 2]
    >>> do_OP_2DUP(s)
    >>> print(s)
    [1, 2, 1, 2]
    """
    stack.append(stack[-2])
    stack.append(stack[-2])


def do_OP_3DUP(stack):
    #  (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
    """
    >>> s = [1, 2, 3]
    >>> do_OP_3DUP(s)
    >>> print(s)
    [1, 2, 3, 1, 2, 3]
    """
    stack.append(stack[-3])
    stack.append(stack[-3])
    stack.append(stack[-3])


def do_OP_2OVER(stack):
    #  (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
    """
    >>> s = [1, 2, 3, 4]
    >>> do_OP_2OVER(s)
    >>> print(s)
    [1, 2, 3, 4, 1, 2]
    """
    stack.append(stack[-4])
    stack.append(stack[-4])


def do_OP_2ROT(stack):
    """
    >>> s = [1, 2, 3, 4, 5, 6]
    >>> do_OP_2ROT(s)
    >>> print(s)
    [3, 4, 5, 6, 1, 2]
    """
    stack.append(stack.pop(-6))
    stack.append(stack.pop(-6))


def do_OP_2SWAP(stack):
    """
    >>> s = [1, 2, 3, 4]
    >>> do_OP_2SWAP(s)
    >>> print(s)
    [3, 4, 1, 2]
    """
    stack.append(stack.pop(-4))
    stack.append(stack.pop(-4))


def do_OP_IFDUP(stack):
    """
    >>> s = [1, 2]
    >>> do_OP_IFDUP(s)
    >>> print(s)
    [1, 2, 2]
    >>> s = [1, 2, 0]
    >>> do_OP_IFDUP(s)
    >>> print(s)
    [1, 2, 0]
    """
    if stack[-1]:
        stack.append(stack[-1])


def do_OP_DROP(stack):
    """
    >>> s = [1, 2]
    >>> do_OP_DROP(s)
    >>> print(s)
    [1]
    """
    stack.pop()


def do_OP_DUP(stack):
    """
    >>> s = [1, 2]
    >>> do_OP_DUP(s)
    >>> print(s)
    [1, 2, 2]
    """
    stack.append(stack[-1])


def do_OP_NIP(stack):
    """
    >>> s = [1, 2]
    >>> do_OP_NIP(s)
    >>> print(s)
    [2]
    """
    v = stack.pop()
    stack.pop()
    stack.append(v)


def do_OP_OVER(stack):
    """
    >>> s = [1, 2]
    >>> do_OP_OVER(s)
    >>> print(s)
    [1, 2, 1]
    """
    stack.append(stack[-2])


def do_OP_ROT(stack):
    """
    >>> s = [1, 2, 3]
    >>> do_OP_ROT(s)
    >>> print(s)
    [2, 3, 1]
    """
    stack.append(stack.pop(-3))


def do_OP_SWAP(stack):
    """
    >>> s = [1, 2, 3]
    >>> do_OP_SWAP(s)
    >>> print(s)
    [1, 3, 2]
    """
    stack.append(stack.pop(-2))


def do_OP_TUCK(stack):
    """
    >>> s = [1, 2, 3]
    >>> do_OP_TUCK(s)
    >>> print(s)
    [1, 3, 2, 3]
    """
    v1 = stack.pop()
    v2 = stack.pop()
    stack.append(v1)
    stack.append(v2)
    stack.append(v1)


def do_OP_CAT(stack):
    """
    >>> s = ["foo", "bar"]
    >>> do_OP_CAT(s)
    >>> print(s)
    ['foobar']
    """
    v1 = stack.pop()
    v2 = stack.pop()
    stack.append(v2 + v1)


def do_OP_RIPEMD160(stack):
    """
    >>> s = [b'foo']
    >>> do_OP_RIPEMD160(s)
    >>> len(s)
    1
    >>> import binascii
    >>> print(binascii.hexlify(s[0]))
    42cfa211018ea492fdee45ac637b7972a0ad6873
    """
    stack.append(ripemd160(stack.pop()).digest())


def do_OP_SHA1(stack):
    """
    >>> s = [b'foo']
    >>> do_OP_SHA1(s)
    >>> len(s)
    1
    >>> import binascii
    >>> print(binascii.hexlify(s[0]))
    0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33
    """
    stack.append(hashlib.sha1(stack.pop()).digest())


def do_OP_SHA256(stack):
    """
    >>> s = [b'foo']
    >>> do_OP_SHA256(s)
    >>> len(s)
    1
    >>> import binascii
    >>> print(binascii.hexlify(s[0]))
    2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    """
    stack.append(hashlib.sha256(stack.pop()).digest())


def do_OP_HASH160(stack):
    """
    >>> s = [b'foo']
    >>> do_OP_HASH160(s)
    >>> len(s)
    1
    >>> import binascii
    >>> print(binascii.hexlify(s[0]))
    e1cf7c8103476b6d7fe9e4979aa10e7c531fcf42
    """
    stack.append(hash160(stack.pop()))


def do_OP_HASH256(stack):
    """
    >>> s = [b'foo']
    >>> do_OP_HASH256(s)
    >>> len(s)
    1
    >>> import binascii
    >>> print(binascii.hexlify(s[0]))
    c7ade88fc7a21498a6a5e5c385e1f68bed822b72aa63c4a9a48a02c2466ee29e
    """
    stack.append(double_sha256(stack.pop()))


if __name__ == "__main__":
    import doctest
    doctest.testmod()
