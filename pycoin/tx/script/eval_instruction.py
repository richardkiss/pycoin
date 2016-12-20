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

from ...intbytes import byte_to_int, int_to_bytes

from . import errno
from . import opcodes
from . import ScriptError

from .check_signature import op_checksig, op_checkmultisig
from .flags import (
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_MINIMALDATA,
    VERIFY_CHECKLOCKTIMEVERIFY,
    VERIFY_MINIMALIF, VERIFY_CHECKSEQUENCEVERIFY,
)
from .microcode import MICROCODE_LOOKUP
from .tools import get_opcode, bool_from_script_bytes, int_from_script_bytes


VERIFY_OPS = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_NUMEQUALVERIFY OP_EQUALVERIFY OP_VERIFY".split())))

NOP_SET = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_NOP1 OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10".split())))


def verify_minimal_data(opcode, data):
    ld = len(data)
    if ld == 0 and opcode == opcodes.OP_0:
        return
    if ld == 1:
        v = byte_to_int(data[0])
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


def make_instruction_lookup():
    instruction_lookup = {}

    VERIFY_OPS = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
        "OP_NUMEQUALVERIFY OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_VERIFY OP_CHECKMULTISIGVERIFY".split())))

    def make_bad_opcode(opcode, even_outside_conditional=False, err=errno.BAD_OPCODE):
        def bad_opcode(ss):
            raise ScriptError("invalid opcode %s at %d" % (
                opcodes.INT_TO_OPCODE.get(opcode, hex(opcode)), ss.pc-1), err)
        bad_opcode.outside_conditional = even_outside_conditional
        return bad_opcode

    DISABLED_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
        "OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_INVERT OP_AND OP_OR OP_XOR OP_2MUL OP_2DIV OP_MUL "
        "OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT".split())))

    BAD_OPCODES_OUTSIDE_IF = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
        "OP_NULLDATA OP_PUBKEYHASH OP_PUBKEY OP_INVALIDOPCODE".split())))

    NOP_SET = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
        "OP_NOP1 OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10".split())))

    def make_from_microcode(f):
        if f.require_minimal:
            def the_f(ss):
                return f(ss.stack, require_minimal=ss.flags & VERIFY_MINIMALDATA)
        else:
            def the_f(ss):
                return f(ss.stack)
        return the_f
    for opcode in MICROCODE_LOOKUP.keys():
        instruction_lookup[opcode] = make_from_microcode(MICROCODE_LOOKUP[opcode])

    BAD_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in ("OP_VERIF OP_VERNOTIF ".split())))
    for opcode in BAD_OPCODE_VALUES:
        instruction_lookup[opcode] = make_bad_opcode(opcode, even_outside_conditional=True)

    for opcode in range(76, 256):
        if opcode not in opcodes.INT_TO_OPCODE:
            instruction_lookup[opcode] = make_bad_opcode(opcode)

    for opcode in DISABLED_OPCODE_VALUES:
        instruction_lookup[opcode] = make_bad_opcode(
            opcode, even_outside_conditional=True, err=errno.DISABLED_OPCODE)

    for opcode in BAD_OPCODES_OUTSIDE_IF:
        instruction_lookup[opcode] = make_bad_opcode(opcode, even_outside_conditional=False)

    def f(ss):
        ss.begin_code_hash = ss.pc
    instruction_lookup[opcodes.OP_CODESEPARATOR] = f

    def f(ss):
        ss.altstack.append(ss.stack.pop())
    instruction_lookup[opcodes.OP_TOALTSTACK] = f

    def f(ss):
        if len(ss.altstack) < 1:
            raise ScriptError("alt stack empty", errno.INVALID_ALTSTACK_OPERATION)
        ss.stack.append(ss.altstack.pop())
    instruction_lookup[opcodes.OP_FROMALTSTACK] = f

    def f(ss):
        ss.stack.append(b'\x81')
    instruction_lookup[opcodes.OP_1NEGATE] = f

    def f(ss):
        ss.expected_hash_type = None  # ### BRAIN DAMAGE
        op_checksig(ss.stack, ss.signature_f, ss.expected_hash_type,
                    ss.script[ss.begin_code_hash:], ss.flags)
    instruction_lookup[opcodes.OP_CHECKSIG] = f

    def f(ss):
        ss.expected_hash_type = None  # ### BRAIN DAMAGE
        op_checksig(ss.stack, ss.signature_f, ss.expected_hash_type,
                    ss.script[ss.begin_code_hash:], ss.flags)
        verify(ss)
    instruction_lookup[opcodes.OP_CHECKSIGVERIFY] = f

    def f(ss):
        ss.expected_hash_type = None  # ### BRAIN DAMAGE
        op_checkmultisig(ss.stack, ss.signature_f,
                         ss.expected_hash_type, ss.script[ss.begin_code_hash:], ss.flags)
    instruction_lookup[opcodes.OP_CHECKMULTISIG] = f

    def f(ss):
        ss.expected_hash_type = None  # ### BRAIN DAMAGE
        op_checkmultisig(ss.stack, ss.signature_f,
                         ss.expected_hash_type, ss.script[ss.begin_code_hash:], ss.flags)
        verify(ss)
    instruction_lookup[opcodes.OP_CHECKMULTISIGVERIFY] = f

    return instruction_lookup

    if opcode in (opcodes.OP_ELSE, opcodes.OP_ENDIF):
        raise ScriptError(
            "%s without OP_IF" % opcodes.INT_TO_OPCODE[opcode], errno.UNBALANCED_CONDITIONAL)

    if opcode == opcodes.OP_CHECKLOCKTIMEVERIFY:
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

    if opcode == opcodes.OP_CHECKSEQUENCEVERIFY:
        if not (ss.flags & VERIFY_CHECKSEQUENCEVERIFY):
            if (ss.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
                raise ScriptError("discouraging nops")
            return
        if len(ss.stack) < 1:
            raise ScriptError("empty stack on CHECKSEQUENCEVERIFY", errno.INVALID_STACK_OPERATION)
        if len(ss.stack[-1]) > 5:
            raise ScriptError("script number overflow", errno.INVALID_STACK_OPERATION+1)
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

    if opcode in VERIFY_OPS:
        v = bool_from_script_bytes(ss.stack.pop())
        if not v:
            err = errno.EQUALVERIFY if opcode is opcodes.OP_EQUALVERIFY else errno.VERIFY
            raise ScriptError("VERIFY failed at %d" % (pc-1), err)


        
    return instruction_lookup

DEFAULT_MICROCODE = make_instruction_lookup()


def eval_instruction(ss, pc, microcode=DEFAULT_MICROCODE):
    opcode, data, new_pc = get_opcode(ss.script, pc)
    ss.pc = new_pc

    require_minimal = ss.flags & VERIFY_MINIMALDATA
    # deal with if_condition_stack first
    all_if_true = functools.reduce(lambda x, y: x and y, ss.if_condition_stack, True)

    if len(ss.stack) + len(ss.altstack) > 1000:
        raise ScriptError("stack has > 1000 items", errno.STACK_SIZE)

    f = DEFAULT_MICROCODE.get(opcode, lambda *args, **kwargs: 0)
    if getattr(f, "outside_conditional", False):
        f(ss)

    if len(ss.if_condition_stack):
        if opcode == opcodes.OP_ELSE:
            ss.if_condition_stack[-1] = not ss.if_condition_stack[-1]
            return
        if opcode == opcodes.OP_ENDIF:
            ss.if_condition_stack.pop()
            return
        if not all_if_true and not (opcodes.OP_IF <= opcode <= opcodes.OP_ENDIF):
            return

    f(ss)

    if opcode in (opcodes.OP_IF, opcodes.OP_NOTIF):
        v = False
        if all_if_true:
            if len(ss.stack) < 1:
                raise ScriptError("IF with no condition", errno.UNBALANCED_CONDITIONAL)
            item = ss.stack.pop()
            if ss.flags & VERIFY_MINIMALIF:
                if item not in (b'', b'\1'):
                    raise ScriptError("non-minimal IF", errno.MINIMALIF)
            v = bool_from_script_bytes(item)
        if opcode == opcodes.OP_NOTIF:
            v = not v
        ss.if_condition_stack.append(v)

    if (ss.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS) and opcode in NOP_SET:
        raise ScriptError("discouraging nops", errno.DISCOURAGE_UPGRADABLE_NOPS)

    if data is not None:
        if require_minimal:
            verify_minimal_data(opcode, data)
        ss.stack.append(data)

    if opcode > opcodes.OP_1NEGATE and opcode <= opcodes.OP_16:
        ss.stack.append(int_to_bytes(opcode + 1 - opcodes.OP_1))

    if opcode in (opcodes.OP_ELSE, opcodes.OP_ENDIF):
        raise ScriptError(
            "%s without OP_IF" % opcodes.INT_TO_OPCODE[opcode], errno.UNBALANCED_CONDITIONAL)

    if opcode == opcodes.OP_CHECKLOCKTIMEVERIFY:
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

    if opcode == opcodes.OP_CHECKSEQUENCEVERIFY:
        if not (ss.flags & VERIFY_CHECKSEQUENCEVERIFY):
            if (ss.flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
                raise ScriptError("discouraging nops")
            return
        if len(ss.stack) < 1:
            raise ScriptError("empty stack on CHECKSEQUENCEVERIFY", errno.INVALID_STACK_OPERATION)
        if len(ss.stack[-1]) > 5:
            raise ScriptError("script number overflow", errno.INVALID_STACK_OPERATION+1)
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

    if opcode in VERIFY_OPS:
        v = bool_from_script_bytes(ss.stack.pop())
        if not v:
            err = errno.EQUALVERIFY if opcode is opcodes.OP_EQUALVERIFY else errno.VERIFY
            raise ScriptError("VERIFY failed at %d" % (pc-1), err)
