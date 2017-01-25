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

import inspect
import hashlib

from . import errno
from . import ScriptError

from .flags import VERIFY_MINIMALDATA
from ...encoding import hash160, double_sha256, ripemd160


def do_OP_NOP(s):
    pass


for i in range(1, 11):
    exec("def do_OP_NOP%d(s): pass" % i)


# BRAIN DAMAGE
def do_OP_1NEGATE(stack):
    stack.append(b'\x81')


def do_OP_RESERVED(stack):
    raise ScriptError("OP_RESERVED encountered", errno.BAD_OPCODE)


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
    >>> print(s == [bytearray([66, 207, 162, 17, 1, 142, 164, 146, 253, 238, 69, 172, 99, 123, 121, 114, 160, 173, 104, 115])])
    True
    """
    stack.append(ripemd160(stack.pop()).digest())


def do_OP_SHA1(stack):
    """
    >>> s = [b'foo']
    >>> do_OP_SHA1(s)
    >>> print(s == [bytearray([11, 238, 199, 181, 234, 63, 15, 219, 201, 93, 13, 212, 127, 60, 91, 194, 117, 218, 138, 51])])
    True
    """
    stack.append(hashlib.sha1(stack.pop()).digest())


def do_OP_SHA256(stack):
    """
    >>> s = [b'foo']
    >>> do_OP_SHA256(s)
    >>> print(s == [bytearray([44, 38, 180, 107, 104, 255, 198, 143, 249, 155, 69, 60, 29, 48, 65, 52, 19, 66, 45, 112, 100, 131, 191, 160, 249, 138, 94, 136, 98, 102, 231, 174])])
    True
    """
    stack.append(hashlib.sha256(stack.pop()).digest())


def do_OP_HASH160(stack):
    """
    >>> s = [b'foo']
    >>> do_OP_HASH160(s)
    >>> print(s == [bytearray([225, 207, 124, 129, 3, 71, 107, 109, 127, 233, 228, 151, 154, 161, 14, 124, 83, 31, 207, 66])])
    True
    """
    stack.append(hash160(stack.pop()))


def do_OP_HASH256(stack):
    """
    >>> s = [b'foo']
    >>> do_OP_HASH256(s)
    >>> print(s == [bytearray([199, 173, 232, 143, 199, 162, 20, 152, 166, 165, 229, 195, 133, 225, 246, 139, 237, 130, 43, 114, 170, 99, 196, 169, 164, 138, 2, 194, 70, 110, 226, 158])])
    True
    """
    stack.append(double_sha256(stack.pop()))


def transform_stack_op(f):
    f.require_minimal = len(inspect.getargspec(f).args) > 1
    if f.require_minimal:
        def the_f(vm):
            return f(vm.stack, require_minimal=vm.flags & VERIFY_MINIMALDATA)
    else:
        def the_f(vm):
            return f(vm.stack)
    return the_f


def all_opcodes():
    d = {}
    the_globals = globals()
    for k, v in list(the_globals.items()):
        if k.startswith("do_OP"):
            d[k[3:]] = transform_stack_op(v)
    return d


if __name__ == "__main__":
    import doctest
    doctest.testmod()
