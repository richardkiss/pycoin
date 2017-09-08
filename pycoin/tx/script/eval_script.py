# -*- coding: utf-8 -*-
"""
Parse, stream, create, sign and verify Bitcoin transactions as Tx structures.


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

import functools

from ...intbytes import byte2int, int2byte

from . import errno
from . import opcodes
from . import ScriptError
from .Stack import Stack

from .check_signature import op_checksig, op_checkmultisig
from .flags import (
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_MINIMALDATA,
    VERIFY_CHECKLOCKTIMEVERIFY,
    VERIFY_MINIMALIF, VERIFY_CHECKSEQUENCEVERIFY,
)
from .microcode import MICROCODE_LOOKUP
from .tools import get_opcode, bool_from_script_bytes, int_from_script_bytes


def verify_minimal_data(opcode, data):
    ld = len(data)
    if ld == 0 and opcode == opcodes.OP_0:
        return
    if ld == 1:
        v = byte2int(data)
        if v == 0x81:
            if opcode == opcodes.OP_1NEGATE:
                return
        elif v == 0 or v > 16:
            return
        elif v == (opcode - 1 + opcodes.OP_1):
            return
    if 1 < ld < 0x4c and opcode == ld:
        return
    if 0x4c <= ld < 256 and opcode == opcodes.OP_PUSHDATA1:
        return
    if 256 < ld < 65536 and opcode == opcodes.OP_PUSHDATA2:
        return
    raise ScriptError("not minimal push of %s" % repr(data), errno.MINIMALDATA)


def verify(ss):
    v = bool_from_script_bytes(ss.stack.pop())
    if not v:
        raise ScriptError("VERIFY failed at %d" % (ss.pc-1), errno.VERIFY)


def make_bad_opcode(opcode, even_outside_conditional=False, err=errno.BAD_OPCODE):
    def bad_opcode(ss):
        raise ScriptError("invalid opcode %s at %d" % (
            opcodes.INT_TO_OPCODE.get(opcode, hex(opcode)), ss.pc-1), err)
    bad_opcode.outside_conditional = even_outside_conditional
    return bad_opcode


def make_from_microcode(f):
    if f.require_minimal:
        def the_f(ss):
            return f(ss.stack, require_minimal=ss.flags & VERIFY_MINIMALDATA)
    else:
        def the_f(ss):
            return f(ss.stack)
    return the_f


def op_code_separator(ss):
    ss.begin_code_hash = ss.pc


def op_toaltstack(ss):
    ss.altstack.append(ss.stack.pop())


def op_fromaltstack(ss):
    if len(ss.altstack) < 1:
        raise ScriptError("alt stack empty", errno.INVALID_ALTSTACK_OPERATION)
    ss.stack.append(ss.altstack.pop())


def op_1negate(ss):
    ss.stack.append(b'\x81')


def op_checksig_1(ss):
    ss.expected_hash_type = None  # ### BRAIN DAMAGE
    op_checksig(ss.stack, ss.signature_f, ss.expected_hash_type,
                ss.script[ss.begin_code_hash:], ss.flags)


def op_checksigverify(ss):
    ss.expected_hash_type = None  # ### BRAIN DAMAGE
    op_checksig(ss.stack, ss.signature_f, ss.expected_hash_type,
                ss.script[ss.begin_code_hash:], ss.flags)
    verify(ss)


def op_checkmultisig_1(ss):
    ss.expected_hash_type = None  # ### BRAIN DAMAGE
    op_checkmultisig(ss.stack, ss.signature_f,
                     ss.expected_hash_type, ss.script[ss.begin_code_hash:], ss.flags)


def op_checkmultisig_verify(ss):
    ss.expected_hash_type = None  # ### BRAIN DAMAGE
    op_checkmultisig(ss.stack, ss.signature_f,
                     ss.expected_hash_type, ss.script[ss.begin_code_hash:], ss.flags)
    verify(ss)


def discourage_nops(ss):
    if (ss.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
        raise ScriptError("discouraging nops", errno.DISCOURAGE_UPGRADABLE_NOPS)


def make_if(reverse_bool=False):
    def f(ss):
        v = False
        all_if_true = functools.reduce(lambda x, y: x and y, ss.if_condition_stack, True)
        if all_if_true:
            if len(ss.stack) < 1:
                raise ScriptError("IF with no condition", errno.UNBALANCED_CONDITIONAL)
            item = ss.stack.pop()
            if ss.flags & VERIFY_MINIMALIF:
                if item not in (b'', b'\1'):
                    raise ScriptError("non-minimal IF", errno.MINIMALIF)
            v = bool_from_script_bytes(item)
        if reverse_bool:
            v = not v
        ss.if_condition_stack.append(v)
    f.outside_conditional = True
    return f


def op_else(ss):
    if len(ss.if_condition_stack) == 0:
        raise ScriptError("OP_ELSE without OP_IF", errno.UNBALANCED_CONDITIONAL)
    ss.if_condition_stack[-1] = not ss.if_condition_stack[-1]


op_else.outside_conditional = True


def op_endif(ss):
    if len(ss.if_condition_stack) == 0:
        raise ScriptError("OP_ENDIF without OP_IF", errno.UNBALANCED_CONDITIONAL)
    ss.if_condition_stack.pop()


op_endif.outside_conditional = True


def check_locktime_verify(ss):
    if not (ss.flags & VERIFY_CHECKLOCKTIMEVERIFY):
        if (ss.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
            raise ScriptError("discouraging nops", errno.DISCOURAGE_UPGRADABLE_NOPS)
        return
    if ss.lock_time is None:
        raise ScriptError("nSequence equal to 0xffffffff")
    if len(ss.stack) < 1:
        raise ScriptError("empty stack on CHECKLOCKTIMEVERIFY")
    if len(ss.stack[-1]) > 5:
        raise ScriptError("script number overflow")
    max_lock_time = int_from_script_bytes(ss.stack[-1])
    if max_lock_time < 0:
        raise ScriptError("top stack item negative on CHECKLOCKTIMEVERIFY")
    era_max = (max_lock_time >= 500000000)
    era_lock_time = (ss.lock_time >= 500000000)
    if era_max != era_lock_time:
        raise ScriptError("eras differ in CHECKLOCKTIMEVERIFY")
    if max_lock_time > ss.lock_time:
        raise ScriptError("nLockTime too soon")


def check_sequence_verify(ss):
    if not (ss.flags & VERIFY_CHECKSEQUENCEVERIFY):
        if (ss.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
            raise ScriptError("discouraging nops", errno.DISCOURAGE_UPGRADABLE_NOPS)
        return
    if len(ss.stack) < 1:
        raise ScriptError("empty stack on CHECKSEQUENCEVERIFY", errno.INVALID_STACK_OPERATION)
    if len(ss.stack[-1]) > 5:
        raise ScriptError("script number overflow", errno.INVALID_STACK_OPERATION+1)
    require_minimal = ss.flags & VERIFY_MINIMALDATA
    sequence = int_from_script_bytes(ss.stack[-1], require_minimal=require_minimal)
    if sequence < 0:
        raise ScriptError(
            "top stack item negative on CHECKSEQUENCEVERIFY", errno.NEGATIVE_LOCKTIME)
    if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        return
    # do the actual check
    if ss.tx_version < 2:
        raise ScriptError("CHECKSEQUENCEVERIFY: bad tx version", errno.UNSATISFIED_LOCKTIME)
    if ss.tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        raise ScriptError("CHECKSEQUENCEVERIFY: locktime disabled")

    # this mask is applied to extract lock-time from the sequence field
    SEQUENCE_LOCKTIME_MASK = 0xffff

    mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK
    sequence_masked = sequence & mask
    tx_sequence_masked = ss.tx_sequence & mask
    if not (((tx_sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG) and
             (sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)) or
            ((tx_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG) and
             (sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG))):
        raise ScriptError("sequence numbers not comparable")
    if sequence_masked > tx_sequence_masked:
        raise ScriptError("sequence number too small")


def make_push_const(opcode):
    v = int2byte(opcode + 1 - opcodes.OP_1)

    def f(ss):
        ss.stack.append(v)
    return f


def make_instruction_lookup():
    instruction_lookup = {}

    for opcode in MICROCODE_LOOKUP.keys():
        instruction_lookup[opcode] = make_from_microcode(MICROCODE_LOOKUP[opcode])

    BAD_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in ("OP_VERIF OP_VERNOTIF ".split())))
    for opcode in BAD_OPCODE_VALUES:
        instruction_lookup[opcode] = make_bad_opcode(opcode, even_outside_conditional=True)

    for opcode in range(76, 256):
        if opcode not in opcodes.INT_TO_OPCODE:
            instruction_lookup[opcode] = make_bad_opcode(opcode)

    DISABLED_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
        "OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_INVERT OP_AND OP_OR OP_XOR OP_2MUL OP_2DIV OP_MUL "
        "OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT".split())))
    for opcode in DISABLED_OPCODE_VALUES:
        instruction_lookup[opcode] = make_bad_opcode(
            opcode, even_outside_conditional=True, err=errno.DISABLED_OPCODE)

    BAD_OPCODES_OUTSIDE_IF = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
        "OP_NULLDATA OP_PUBKEYHASH OP_PUBKEY OP_INVALIDOPCODE".split())))
    for opcode in BAD_OPCODES_OUTSIDE_IF:
        instruction_lookup[opcode] = make_bad_opcode(opcode, even_outside_conditional=False)

    instruction_lookup[opcodes.OP_CODESEPARATOR] = op_code_separator
    instruction_lookup[opcodes.OP_TOALTSTACK] = op_toaltstack
    instruction_lookup[opcodes.OP_FROMALTSTACK] = op_fromaltstack
    instruction_lookup[opcodes.OP_1NEGATE] = op_1negate
    instruction_lookup[opcodes.OP_CHECKSIG] = op_checksig_1
    instruction_lookup[opcodes.OP_CHECKSIGVERIFY] = op_checksigverify
    instruction_lookup[opcodes.OP_CHECKMULTISIG] = op_checkmultisig_1
    instruction_lookup[opcodes.OP_CHECKMULTISIGVERIFY] = op_checkmultisig_verify

    NOP_SET = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
        "OP_NOP1 OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10".split())))
    for opcode in NOP_SET:
        instruction_lookup[opcode] = discourage_nops

    instruction_lookup[opcodes.OP_CHECKLOCKTIMEVERIFY] = check_locktime_verify
    instruction_lookup[opcodes.OP_CHECKSEQUENCEVERIFY] = check_sequence_verify

    instruction_lookup[opcodes.OP_IF] = make_if()
    instruction_lookup[opcodes.OP_NOTIF] = make_if(reverse_bool=True)

    instruction_lookup[opcodes.OP_ELSE] = op_else
    instruction_lookup[opcodes.OP_ENDIF] = op_endif

    for opcode in range(opcodes.OP_1, opcodes.OP_16+1):
        instruction_lookup[opcode] = make_push_const(opcode)

    return instruction_lookup


DEFAULT_MICROCODE = make_instruction_lookup()


def eval_instruction(ss, pc, microcode=DEFAULT_MICROCODE):
    opcode, data, new_pc = get_opcode(ss.script, pc)
    ss.pc = new_pc

    all_if_true = functools.reduce(lambda x, y: x and y, ss.if_condition_stack, True)
    if data is not None and all_if_true:
        if ss.flags & VERIFY_MINIMALDATA:
            verify_minimal_data(opcode, data)
        ss.stack.append(data)

    f = DEFAULT_MICROCODE.get(opcode, lambda *args, **kwargs: 0)
    if getattr(f, "outside_conditional", False) or all_if_true:
        f(ss)


"""
WHICH SCRIPT:
I: tx in script
O: tx out script
H: pay to script hash script
D: witness data
W: witness script
"""


class ScriptState(object):
    def __init__(self, script, signature_f, lock_time, stack, altstack,
                 flags, tx_sequence, tx_version, if_condition_stack, which_script):
        self.script = script
        self.signature_f = signature_f
        self.lock_time = lock_time
        self.stack = stack
        self.altstack = altstack
        self.flags = flags
        self.tx_sequence = tx_sequence
        self.tx_version = tx_version
        self.if_condition_stack = if_condition_stack
        self.which_script = which_script
        self.begin_code_hash = 0  # ### BRAIN DAMAGE
        self.pc = 0  # ### BRAIN DAMAGE


def post_script_check(stack, altstack, if_condition_stack):
    if len(if_condition_stack):
        raise ScriptError("missing ENDIF", errno.UNBALANCED_CONDITIONAL)

    if len(stack) + len(altstack) > 1000:
        raise ScriptError("stack has > 1000 items", errno.STACK_SIZE)


def eval_script(script, signature_for_hash_type_f, lock_time, expected_hash_type=None, stack=[],
                disallow_long_scripts=True, traceback_f=None, is_signature=False, flags=0,
                tx_sequence=None, tx_version=None):
    altstack = Stack()
    if disallow_long_scripts and len(script) > 10000:
        raise ScriptError("script too long", errno.SCRIPT_SIZE)

    pc = 0
    if_condition_stack = []
    op_count = 0

    ss = ScriptState(script, signature_for_hash_type_f, lock_time, stack, altstack,
                     flags, tx_sequence, tx_version, if_condition_stack, which_script="FOO")

    while pc < len(script):
        old_pc = pc
        opcode, data, pc = get_opcode(script, pc)

        if traceback_f:
            traceback_f(old_pc, opcode, data, stack, altstack, if_condition_stack, is_signature)

        if data and len(data) > 520 and disallow_long_scripts:
            raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)
        if opcode > opcodes.OP_16:
            op_count += 1
        stack_top = stack[-1] if stack else b''

        if len(stack) + len(altstack) > 1000:
            raise ScriptError("stack has > 1000 items", errno.STACK_SIZE)
        eval_instruction(ss, old_pc)

        if opcode in (opcodes.OP_CHECKMULTISIG, opcodes.OP_CHECKMULTISIGVERIFY):
            op_count += int_from_script_bytes(stack_top)
        if op_count > 201:
            raise ScriptError("script contains too many operations", errno.OP_COUNT)

    post_script_check(stack, altstack, if_condition_stack)
