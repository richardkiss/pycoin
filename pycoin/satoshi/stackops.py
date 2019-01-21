import hashlib

from . import errno
from pycoin.coins.SolutionChecker import ScriptError

from ..encoding.hash import hash160, double_sha256, ripemd160


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
    stack.pop()
    stack.pop()


def do_OP_2DUP(stack):
    #  (x1 x2 -- x1 x2 x1 x2)
    stack.append(stack[-2])
    stack.append(stack[-2])


def do_OP_3DUP(stack):
    #  (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
    stack.append(stack[-3])
    stack.append(stack[-3])
    stack.append(stack[-3])


def do_OP_2OVER(stack):
    #  (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
    stack.append(stack[-4])
    stack.append(stack[-4])


def do_OP_2ROT(stack):
    # (1, 2, 3, 4, 5, 6 -- 3, 4, 5, 6, 1, 2)
    stack.append(stack.pop(-6))
    stack.append(stack.pop(-6))


def do_OP_2SWAP(stack):
    stack.append(stack.pop(-4))
    stack.append(stack.pop(-4))


def do_OP_IFDUP(stack):
    if stack[-1]:
        stack.append(stack[-1])


def do_OP_DROP(stack):
    stack.pop()


def do_OP_DUP(stack):
    stack.append(stack[-1])


def do_OP_NIP(stack):
    v = stack.pop()
    stack.pop()
    stack.append(v)


def do_OP_OVER(stack):
    stack.append(stack[-2])


def do_OP_ROT(stack):
    stack.append(stack.pop(-3))


def do_OP_SWAP(stack):
    stack.append(stack.pop(-2))


def do_OP_TUCK(stack):
    v1 = stack.pop()
    v2 = stack.pop()
    stack.append(v1)
    stack.append(v2)
    stack.append(v1)


def do_OP_CAT(stack):
    v1 = stack.pop()
    v2 = stack.pop()
    stack.append(v2 + v1)


def do_OP_RIPEMD160(stack):
    stack.append(ripemd160(stack.pop()).digest())


def do_OP_SHA1(stack):
    stack.append(hashlib.sha1(stack.pop()).digest())


def do_OP_SHA256(stack):
    stack.append(hashlib.sha256(stack.pop()).digest())


def do_OP_HASH160(stack):
    stack.append(hash160(stack.pop()))


def do_OP_HASH256(stack):
    stack.append(double_sha256(stack.pop()))


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
