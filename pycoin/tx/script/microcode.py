
import binascii

from .opcodes import OPCODE_TO_INT

from ...encoding import ripemd160_sha, double_sha256

def as_bignum(s):
    v = 0
    b = 0
    for c in s:
        v += (c << b)
        b += 8
    return v

def from_bignum(v):
    l = []
    while v > 0:
        v, mod = divmod(v, 256)
        l.append(mod)
    return bytes(l)

VCH_TRUE = '\1\1'
VCH_FALSE = '\0'

do_OP_NOP = do_OP_NOP1 = do_OP_NOP2 = do_OP_NOP3 = do_OP_NOP4 = do_OP_NOP5 = lambda s: None
do_OP_NOP6 = do_OP_NOP7 = do_OP_NOP8 = do_OP_NOP9 = do_OP_NOP10 = lambda s: None

def do_OP_VERIFY(stack):
    pass

def do_OP_RETURN(stack):
    raise ScriptError("OP_RETURN encountered")

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
    #// (x1 x2 -- x1 x2 x1 x2)
    """
    >>> s = [1, 2]
    >>> do_OP_2DUP(s)
    >>> print(s)
    [1, 2, 1, 2]
    """
    stack.append(stack[-2])
    stack.append(stack[-2])

def do_OP_3DUP(stack):
    #// (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
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
    #// (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
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
    stack.append(len(stack))

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

def do_OP_PICK(stack):
    """
    >>> s = ['a', 'b', 'c', 'd', bytes([2])]
    >>> do_OP_PICK(s)
    >>> print(s)
    ['a', 'b', 'c', 'd', 'b']
    """
    v = as_bignum(stack.pop())
    stack.append(stack[-v-1])

def do_OP_ROLL(stack):
    """
    >>> s = ['a', 'b', 'c', 'd', bytes([2])]
    >>> do_OP_ROLL(s)
    >>> print(s)
    ['a', 'c', 'd', 'b']
    """
    v = as_bignum(stack.pop())
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
    >>> s = ['abcdef', chr(3), chr(2)]
    >>> do_OP_SUBSTR(s)
    >>> print(s)
    ['de']
    """
    pos = as_bignum(stack.pop())
    length = as_bignum(stack.pop())
    stack.append(stack.pop()[length:length+pos])

def do_OP_LEFT(stack):
    """
    >>> s = ['abcdef', chr(3)]
    >>> do_OP_LEFT(s)
    >>> print(s)
    ['abc']
    """
    pos = as_bignum(stack.pop())
    stack.append(stack.pop()[:pos])

def do_OP_RIGHT(stack):
    """
    >>> s = ['abcdef', chr(3)]
    >>> do_OP_RIGHT(s)
    >>> print(s)
    ['def']
    """
    pos = as_bignum(stack.pop())
    stack.append(stack.pop()[-pos:])

def do_OP_SIZE(stack):
    """
    >>> s = [b'abcdef']
    >>> do_OP_SIZE(s)
    >>> print(s)
    [b'abcdef', b'\\x06']
    >>> s = [b'abcdef'*1000]
    >>> do_OP_SIZE(s)
    >>> print(binascii.hexlify(s[-1]))
    b'7017'
    """
    stack.append(from_bignum(len(stack[-1])))

def do_OP_INVERT(stack):
    """
    >>> s = [binascii.unhexlify('5dcf39822aebc166')]
    >>> do_OP_INVERT(s)
    >>> print(binascii.hexlify(s[0]))
    b'a230c67dd5143e99'
    """
    v = stack.pop()
    stack.append(bytes((s^0xff) for s in v))

def make_same_size(v1, v2):
    larger = max(len(v1), len(v2))
    nulls = b'\0' * larger
    v1 = (v1 + nulls)[:larger]
    v2 = (v2 + nulls)[:larger]
    return v1, v2

def make_bitwise_bin_op(binop):
    """
    >>> s = [binascii.unhexlify('5dcf39832aebc166'), binascii.unhexlify('ff00f086') ]
    >>> do_OP_AND(s)
    >>> print(binascii.hexlify(s[0]))
    b'5d00308200000000'
    >>> s = [binascii.unhexlify('5dcf39832aebc166'), binascii.unhexlify('ff00f086') ]
    >>> do_OP_OR(s)
    >>> print(binascii.hexlify(s[0]))
    b'ffcff9872aebc166'
    >>> s = [binascii.unhexlify('5dcf39832aebc166'), binascii.unhexlify('ff00f086') ]
    >>> do_OP_XOR(s)
    >>> print(binascii.hexlify(s[0]))
    b'a2cfc9052aebc166'
    >>> s = []
    """
    def f(stack):
        v1 = stack.pop()
        v2 = stack.pop()
        v1, v2 = make_same_size(v1, v2)
        stack.append(bytes(binop(v1[i], v2[i]) for i in range(len(v1))))
    return f

do_OP_AND = make_bitwise_bin_op(lambda x,y: x & y)
do_OP_OR = make_bitwise_bin_op(lambda x,y: x | y)
do_OP_XOR = make_bitwise_bin_op(lambda x,y: x ^ y)

def make_bool(v):
    if v: return VCH_TRUE
    return VCH_FALSE

def do_OP_EQUAL(stack):
    v1 = stack.pop()
    v2 = stack.pop()
    stack.append(make_bool(v1 == v2))

do_OP_EQUALVERIFY = do_OP_EQUAL

def make_bin_op(binop):
    def f(stack):
        v1 = as_bignum(stack.pop())
        v2 = as_bignum(stack.pop())
        stack.append(from_bignum(binop(v2, v1)))
    return f

do_OP_ADD = make_bin_op(lambda x,y: x+y)
do_OP_SUB = make_bin_op(lambda x,y: x-y)
do_OP_MUL = make_bin_op(lambda x,y: x*y)
do_OP_DIV = make_bin_op(lambda x,y: x//y)
do_OP_MOD = make_bin_op(lambda x,y: x%y)
do_OP_LSHIFT = make_bin_op(lambda x,y: x<<y)
do_OP_RSHIFT = make_bin_op(lambda x,y: x>>y)
do_OP_BOOLAND = make_bin_op(lambda x,y: x and y)
do_OP_BOOLOR = make_bin_op(lambda x,y: x or y)
do_OP_NUMEQUAL = make_bin_op(lambda x,y: x==y)
do_OP_NUMEQUALVERIFY = make_bin_op(lambda x,y: x==y)
do_OP_NUMNOTEQUAL = make_bin_op(lambda x,y: x!=y)
do_OP_LESSTHAN = make_bin_op(lambda x,y: x<y)
do_OP_GREATERTHAN = make_bin_op(lambda x,y: x>y)
do_OP_LESSTHANOREQUAL = make_bin_op(lambda x,y: x<=y)
do_OP_GREATERTHANOREQUAL = make_bin_op(lambda x,y: x>=y)
do_OP_MIN = make_bin_op(min)
do_OP_MAX = make_bin_op(max)

def do_OP_WITHIN(stack):
    v3 = stack.pop()
    v2 = stack.pop()
    v1 = stack.pop()
    ok = (v3 <= v2 <= v1)
    stack.append(make_bool(ok))

def do_OP_RIPEMD160(stack):
    stack.append(ripmemd160(stack.pop()))

def do_OP_SHA1(stack):
    stack.append(hashlib.sha1(stack.pop()).digest())

def do_OP_SHA256(stack):
    stack.append(hashlib.sha256(stack.pop()).digest())

def do_OP_HASH160(stack):
    stack.append(ripemd160_sha(stack.pop()))

def do_OP_HASH256(stack):
    stack.append(double_sha256(stack.pop()).digest())

def make_unary_num_op(unary_f):
    def f(stack):
        stack.append(from_bignum(unary_f(as_bignum(stack.pop()))))
    return f

do_OP_1ADD = make_unary_num_op(lambda x: x+1)
do_OP_1SUB = make_unary_num_op(lambda x: x-1)
do_OP_2MUL = make_unary_num_op(lambda x: x<<1)
do_OP_2DIV = make_unary_num_op(lambda x: x>>1)
do_OP_NEGATE = make_unary_num_op(lambda x: -x)
do_OP_ABS = make_unary_num_op(lambda x: abs(x))
do_OP_NOT = make_unary_num_op(lambda x: make_bool(x == 0))
do_OP_0NOTEQUAL = make_unary_num_op(lambda x: make_bool(x != 0))

def build_ops_lookup():
    d = {}
    the_globals = globals()
    for opcode_name, opcode_int in OPCODE_TO_INT.items():
        do_f_name = "do_%s" % opcode_name
        if do_f_name in the_globals:
            d[opcode_int] = the_globals[do_f_name]
    return d

MICROCODE_LOOKUP = build_ops_lookup()

if __name__ == "__main__":
    import doctest
    doctest.testmod()
