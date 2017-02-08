# -*- coding: utf-8 -*-
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
import inspect

from . import errno
from . import ScriptError

from .opcodes import INT_TO_OPCODE
from .tools import bool_from_script_bytes, bool_to_script_bytes, int_to_script_bytes, int_from_script_bytes
from ...encoding import hash160, double_sha256, ripemd160


VCH_TRUE = b'\1'
VCH_FALSE = b''

do_OP_NOP = do_OP_NOP1 = do_OP_NOP2 = do_OP_NOP3 = do_OP_NOP4 = do_OP_NOP5 = lambda s: None
do_OP_NOP6 = do_OP_NOP7 = do_OP_NOP8 = do_OP_NOP9 = do_OP_NOP10 = lambda s: None


def nonnegative_int_from_script_bytes(b, require_minimal):
    v = int_from_script_bytes(b, require_minimal=require_minimal)
    if v < 0:
        raise ScriptError("unexpectedly got negative value", errno.INVALID_STACK_OPERATION)
    return v


def do_OP_0(stack):
    stack.append(b'')


def do_OP_RESERVED(stack):
    raise ScriptError("OP_RESERVED encountered", errno.BAD_OPCODE)


def do_OP_VER(stack):
    raise ScriptError("OP_VER encountered", errno.BAD_OPCODE)


def do_OP_RESERVED1(stack):
    raise ScriptError("OP_RESERVED1 encountered", errno.BAD_OPCODE)


def do_OP_RESERVED2(stack):
    raise ScriptError("OP_RESERVED2 encountered", errno.BAD_OPCODE)


def do_OP_VERIFY(stack):
    pass


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


def do_OP_DEPTH(stack):
    """
    >>> s = [1, 2, 1, 2, 1, 2]
    >>> do_OP_DEPTH(s)
    >>> print(s)
    [1, 2, 1, 2, 1, 2, 6]
    """
    stack.append(int_to_script_bytes(len(stack)))


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


def do_OP_PICK(stack, require_minimal):
    """
    >>> s = ['a', 'b', 'c', 'd', b'\2']
    >>> do_OP_PICK(s)
    >>> print(s)
    ['a', 'b', 'c', 'd', 'b']
    """
    v = nonnegative_int_from_script_bytes(stack.pop(), require_minimal=require_minimal)
    stack.append(stack[-v-1])


def do_OP_ROLL(stack, require_minimal):
    """
    >>> s = ['a', 'b', 'c', 'd', b'\2']
    >>> do_OP_ROLL(s)
    >>> print(s)
    ['a', 'c', 'd', 'b']
    """
    v = nonnegative_int_from_script_bytes(stack.pop(), require_minimal=require_minimal)
    stack.append(stack.pop(-v-1))


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


def do_OP_SUBSTR(stack):
    """
    >>> s = ['abcdef', b'\3', b'\2']
    >>> do_OP_SUBSTR(s)
    >>> print(s)
    ['de']
    """
    pos = nonnegative_int_from_script_bytes(stack.pop())
    length = nonnegative_int_from_script_bytes(stack.pop())
    stack.append(stack.pop()[length:length+pos])


def do_OP_LEFT(stack):
    """
    >>> s = [b'abcdef', b'\\3']
    >>> do_OP_LEFT(s)
    >>> print(len(s)==1 and s[0]==b'abc')
    True
    >>> s = [b'abcdef', b'\\0']
    >>> do_OP_LEFT(s)
    >>> print(len(s) ==1 and s[0]==b'')
    True
    """
    pos = nonnegative_int_from_script_bytes(stack.pop())
    stack.append(stack.pop()[:pos])


def do_OP_RIGHT(stack):
    """
    >>> s = [b'abcdef', b'\\3']
    >>> do_OP_RIGHT(s)
    >>> print(s==[b'def'])
    True
    >>> s = [b'abcdef', b'\\0']
    >>> do_OP_RIGHT(s)
    >>> print(s==[b''])
    True
    """
    pos = nonnegative_int_from_script_bytes(stack.pop())
    if pos > 0:
        stack.append(stack.pop()[-pos:])
    else:
        stack.pop()
        stack.append(b'')


def do_OP_SIZE(stack):
    """
    >>> s = [b'abcdef']
    >>> do_OP_SIZE(s)
    >>> print(s == [b'abcdef', b'\x06'])
    True
    >>> s = [b'abcdef'*1000]
    >>> do_OP_SIZE(s)
    >>> print(binascii.hexlify(s[-1]) == b'1770')
    True
    """
    stack.append(int_to_script_bytes(len(stack[-1])))


def make_same_size(v1, v2):
    larger = max(len(v1), len(v2))
    nulls = b'\0' * larger
    v1 = (v1 + nulls)[:larger]
    v2 = (v2 + nulls)[:larger]
    return v1, v2


def do_OP_EQUAL(stack):
    """
    >>> s = [b'string1', b'string1']
    >>> do_OP_EQUAL(s)
    >>> print(s == [VCH_TRUE])
    True
    >>> s = [b'string1', b'string2']
    >>> do_OP_EQUAL(s)
    >>> print(s == [VCH_FALSE])
    True
    """
    v1, v2 = [stack.pop() for i in range(2)]
    stack.append(bool_to_script_bytes(v1 == v2))


do_OP_EQUALVERIFY = do_OP_EQUAL


def pop_check_bounds(stack, require_minimal):
    v = stack.pop()
    if len(v) > 4:
        raise ScriptError("overflow in binop", errno.UNKNOWN_ERROR)
    return int_from_script_bytes(v, require_minimal=require_minimal)


def make_bin_op(binop):
    def f(stack, require_minimal):
        v1, v2 = [pop_check_bounds(stack, require_minimal) for i in range(2)]
        stack.append(int_to_script_bytes(binop(v2, v1)))
    return f


def make_bool_bin_op(binop):
    def f(stack, require_minimal):
        v1, v2 = [pop_check_bounds(stack, require_minimal) for i in range(2)]
        stack.append(bool_to_script_bytes(binop(v2, v1)))
    return f

do_OP_ADD = make_bin_op(lambda x, y: x + y)
do_OP_SUB = make_bin_op(lambda x, y: x - y)
do_OP_MUL = make_bin_op(lambda x, y: x * y)
do_OP_DIV = make_bin_op(lambda x, y: x // y)
do_OP_MOD = make_bin_op(lambda x, y: x % y)
do_OP_LSHIFT = make_bin_op(lambda x, y: x << y)
do_OP_RSHIFT = make_bin_op(lambda x, y: x >> y)
do_OP_BOOLAND = make_bool_bin_op(lambda x, y: x and y)
do_OP_BOOLOR = make_bool_bin_op(lambda x, y: x or y)
do_OP_NUMEQUAL = make_bool_bin_op(lambda x, y: x == y)
do_OP_NUMEQUALVERIFY = make_bool_bin_op(lambda x, y: x == y)
do_OP_NUMNOTEQUAL = make_bool_bin_op(lambda x, y: x != y)
do_OP_LESSTHAN = make_bool_bin_op(lambda x, y: x < y)
do_OP_GREATERTHAN = make_bool_bin_op(lambda x, y: x > y)
do_OP_LESSTHANOREQUAL = make_bool_bin_op(lambda x, y: x <= y)
do_OP_GREATERTHANOREQUAL = make_bool_bin_op(lambda x, y: x >= y)
do_OP_MIN = make_bin_op(min)
do_OP_MAX = make_bin_op(max)


def do_OP_WITHIN(stack, require_minimal):
    """
    >>> s = [b'c', b'b', b'a']
    >>> do_OP_WITHIN(s)
    >>> print(s == [VCH_TRUE])
    True
    >>> s = [b'b', b'c', b'a']
    >>> do_OP_WITHIN(s)
    >>> print(s == [VCH_FALSE])
    True
    """
    v3, v2, v1 = [int_from_script_bytes(stack.pop(), require_minimal=require_minimal) for i in range(3)]
    ok = (v2 <= v1 < v3)
    stack.append(bool_to_script_bytes(ok))


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


def make_unary_num_op(unary_f):
    def f(stack, require_minimal):
        stack.append(int_to_script_bytes(unary_f(pop_check_bounds(stack, require_minimal))))
    return f

do_OP_1ADD = make_unary_num_op(lambda x: x + 1)
do_OP_1SUB = make_unary_num_op(lambda x: x - 1)
do_OP_2MUL = make_unary_num_op(lambda x: x << 1)
do_OP_2DIV = make_unary_num_op(lambda x: x >> 1)
do_OP_NEGATE = make_unary_num_op(lambda x: -x)
do_OP_ABS = make_unary_num_op(lambda x: abs(x))


def do_OP_NOT(stack, require_minimal):
    return stack.append(bool_to_script_bytes(not pop_check_bounds(stack, require_minimal)))


def do_OP_0NOTEQUAL(stack, require_minimal):
    return stack.append(int_to_script_bytes(bool_from_script_bytes(
                stack.pop(), require_minimal=require_minimal)))


def build_ops_lookup():
    d = {}
    the_globals = globals()
    for opcode_int, opcode_name in INT_TO_OPCODE.items():
        do_f_name = "do_%s" % opcode_name
        if do_f_name in the_globals:
            f = the_globals[do_f_name]
            f.require_minimal = len(inspect.getargspec(f).args) > 1
            d[opcode_int] = f
    return d

MICROCODE_LOOKUP = build_ops_lookup()

if __name__ == "__main__":
    import doctest
    doctest.testmod()
