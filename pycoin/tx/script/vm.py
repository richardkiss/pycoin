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

from hashlib import sha256

from ...intbytes import byte_to_int, int_to_bytes

from . import errno
from . import opcodes
from . import ScriptError

from .check_signature import op_checksig, op_checkmultisig
from .flags import (
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
    VERIFY_P2SH, VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_MINIMALDATA,
    VERIFY_SIGPUSHONLY, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CLEANSTACK,
    VERIFY_WITNESS, VERIFY_MINIMALIF, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_WITNESS_PUBKEYTYPE, VERIFY_CHECKSEQUENCEVERIFY,
)
from .microcode import MICROCODE_LOOKUP
from .tools import get_opcode, bin_script, bool_from_script_bytes, int_from_script_bytes


VERIFY_OPS = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_NUMEQUALVERIFY OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_VERIFY OP_CHECKMULTISIGVERIFY".split())))

BAD_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in ("OP_VERIF OP_VERNOTIF ".split())))

DISABLED_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_INVERT OP_AND OP_OR OP_XOR OP_2MUL OP_2DIV OP_MUL "
    "OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT".split())))

BAD_OPCODES_OUTSIDE_IF = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_NULLDATA OP_PUBKEYHASH OP_PUBKEY OP_INVALIDOPCODE".split())))

NOP_SET = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_NOP1 OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10".split())))


class Stack(list):
    def pop(self, *args, **kwargs):
        try:
            return super(Stack, self).pop(*args, **kwargs)
        except IndexError:
            raise ScriptError("pop from empty stack", errno.INVALID_STACK_OPERATION)

    def __getitem__(self, *args, **kwargs):
        try:
            return super(Stack, self).__getitem__(*args, **kwargs)
        except IndexError:
            raise ScriptError("getitem out of range", errno.INVALID_STACK_OPERATION)


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


def eval_script(script, signature_for_hash_type_f, lock_time, expected_hash_type=None, stack=[],
                disallow_long_scripts=True, traceback_f=None, is_signature=False, flags=0,
                tx_sequence=None, tx_version=None):
    altstack = Stack()
    if disallow_long_scripts and len(script) > 10000:
        raise ScriptError("script too long", errno.SCRIPT_SIZE)

    pc = 0
    begin_code_hash = pc
    if_condition_stack = []
    op_count = 0
    require_minimal = flags & VERIFY_MINIMALDATA

    while pc < len(script):
        old_pc = pc
        opcode, data, pc = get_opcode(script, pc)
        if traceback_f:
            traceback_f(old_pc, opcode, data, stack, altstack, if_condition_stack, is_signature)
        # deal with if_condition_stack first
        all_if_true = functools.reduce(lambda x, y: x and y, if_condition_stack, True)

        if opcode > opcodes.OP_16:
            op_count += 1
            if op_count > 201:
                raise ScriptError("script contains too many operations", errno.OP_COUNT)

        if len(stack) + len(altstack) > 1000:
            raise ScriptError("stack has > 1000 items", errno.STACK_SIZE)

        if opcode in BAD_OPCODE_VALUES:
            raise ScriptError("invalid opcode %s at %d" % (
                    opcodes.INT_TO_OPCODE.get(opcode, hex(opcode)), pc-1), errno.BAD_OPCODE)

        if opcode in DISABLED_OPCODE_VALUES:
            raise ScriptError("invalid opcode %s at %d" % (
                    opcodes.INT_TO_OPCODE.get(opcode, hex(opcode)), pc-1), errno.DISABLED_OPCODE)

        if data and len(data) > 520 and disallow_long_scripts:
            raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)

        if len(if_condition_stack):
            if opcode == opcodes.OP_ELSE:
                if_condition_stack[-1] = not if_condition_stack[-1]
                continue
            if opcode == opcodes.OP_ENDIF:
                if_condition_stack.pop()
                continue
            if not all_if_true and not (opcodes.OP_IF <= opcode <= opcodes.OP_ENDIF):
                continue

        if opcode in (opcodes.OP_IF, opcodes.OP_NOTIF):
            v = False
            if all_if_true:
                if len(stack) < 1:
                    raise ScriptError("IF with no condition", errno.UNBALANCED_CONDITIONAL)
                item = stack.pop()
                if flags & VERIFY_MINIMALIF:
                    if item not in (b'', b'\1'):
                        raise ScriptError("non-minimal IF", errno.MINIMALIF)
                v = bool_from_script_bytes(item)
            if opcode == opcodes.OP_NOTIF:
                v = not v
            if_condition_stack.append(v)
            continue

        if opcode in BAD_OPCODES_OUTSIDE_IF:
            raise ScriptError("invalid opcode %s at %d" % (
                    opcodes.INT_TO_OPCODE.get(opcode, hex(opcode)), pc-1), errno.BAD_OPCODE)

        if opcode > 76 and opcode not in opcodes.INT_TO_OPCODE:
            raise ScriptError("invalid opcode %s at %d" % (
                    opcodes.INT_TO_OPCODE.get(opcode, hex(opcode)), pc-1), errno.BAD_OPCODE)

        if (flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS) and opcode in NOP_SET:
            raise ScriptError("discouraging nops", errno.DISCOURAGE_UPGRADABLE_NOPS)

        if data is not None:
            if require_minimal:
                verify_minimal_data(opcode, data)
            stack.append(data)
            continue

        if opcode == opcodes.OP_CODESEPARATOR:
            begin_code_hash = pc
            continue

        if opcode in MICROCODE_LOOKUP:
            f = MICROCODE_LOOKUP[opcode]
            if f.require_minimal:
                f(stack, require_minimal=require_minimal)
            else:
                f(stack)

            if opcode in VERIFY_OPS:
                v = bool_from_script_bytes(stack.pop())
                if not v:
                    err = errno.EQUALVERIFY if opcode is opcodes.OP_EQUALVERIFY else errno.VERIFY
                    raise ScriptError("VERIFY failed at %d" % (pc-1), err)
            continue

        if opcode == opcodes.OP_TOALTSTACK:
            altstack.append(stack.pop())
            continue

        if opcode == opcodes.OP_FROMALTSTACK:
            if len(altstack) < 1:
                raise ScriptError("alt stack empty", errno.INVALID_ALTSTACK_OPERATION)
            stack.append(altstack.pop())
            continue

        if opcode == opcodes.OP_1NEGATE:
            stack.append(b'\x81')
            continue

        if opcode > opcodes.OP_1NEGATE and opcode <= opcodes.OP_16:
            stack.append(int_to_bytes(opcode + 1 - opcodes.OP_1))
            continue

        if opcode in (opcodes.OP_ELSE, opcodes.OP_ENDIF):
            raise ScriptError(
                "%s without OP_IF" % opcodes.INT_TO_OPCODE[opcode], errno.UNBALANCED_CONDITIONAL)

        if opcode in (opcodes.OP_CHECKSIG, opcodes.OP_CHECKSIGVERIFY):
            # Subset of script starting at the most recent codeseparator
            op_checksig(stack, signature_for_hash_type_f, expected_hash_type, script[begin_code_hash:],
                        flags)
            if opcode == opcodes.OP_CHECKSIGVERIFY:
                if not bool_from_script_bytes(stack.pop()):
                    raise ScriptError("VERIFY failed at %d" % (pc-1), errno.VERIFY)
            continue

        if opcode in (opcodes.OP_CHECKMULTISIG, opcodes.OP_CHECKMULTISIGVERIFY):
            # Subset of script starting at the most recent codeseparator
            n_ops = op_checkmultisig(
                stack, signature_for_hash_type_f, expected_hash_type, script[begin_code_hash:], flags)
            op_count += n_ops
            if op_count > 201:
                raise ScriptError("script contains too many operations", errno.OP_COUNT)

        if opcode == opcodes.OP_CHECKLOCKTIMEVERIFY:
            if not (flags & VERIFY_CHECKLOCKTIMEVERIFY):
                if (flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
                    raise ScriptError("discouraging nops", errno.DISCOURAGE_UPGRADABLE_NOPS)
                continue
            if lock_time is None:
                raise ScriptError("nSequence equal to 0xffffffff")
            if len(stack) < 1:
                raise ScriptError("empty stack on CHECKLOCKTIMEVERIFY")
            if len(stack[-1]) > 5:
                raise ScriptError("script number overflow")
            max_lock_time = int_from_script_bytes(stack[-1])
            if max_lock_time < 0:
                raise ScriptError("top stack item negative on CHECKLOCKTIMEVERIFY")
            era_max = (max_lock_time >= 500000000)
            era_lock_time = (lock_time >= 500000000)
            if era_max != era_lock_time:
                raise ScriptError("eras differ in CHECKLOCKTIMEVERIFY")
            if max_lock_time > lock_time:
                raise ScriptError("nLockTime too soon")
            continue

        if opcode == opcodes.OP_CHECKSEQUENCEVERIFY:
            if not (flags & VERIFY_CHECKSEQUENCEVERIFY):
                if (flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
                    raise ScriptError("discouraging nops")
                continue
            if len(stack) < 1:
                raise ScriptError("empty stack on CHECKSEQUENCEVERIFY", errno.INVALID_STACK_OPERATION)
            if len(stack[-1]) > 5:
                raise ScriptError("script number overflow", errno.INVALID_STACK_OPERATION+1)
            sequence = int_from_script_bytes(stack[-1], require_minimal=require_minimal)
            if sequence < 0:
                raise ScriptError(
                    "top stack item negative on CHECKSEQUENCEVERIFY", errno.NEGATIVE_LOCKTIME)
            if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
                continue
            # do the actual check
            if tx_version < 2:
                raise ScriptError("CHECKSEQUENCEVERIFY: bad tx version", errno.UNSATISFIED_LOCKTIME)
            if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
                raise ScriptError("CHECKSEQUENCEVERIFY: locktime disabled")

            # this mask is applied to extract lock-time from the sequence field
            SEQUENCE_LOCKTIME_MASK = 0xffff

            mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK
            sequence_masked = sequence & mask
            tx_sequence_masked = tx_sequence & mask
            if not (((tx_sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG) and
                     (sequence_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)) or
                    ((tx_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG) and
                     (sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG))):
                raise ScriptError("sequence numbers not comparable")
            if sequence_masked > tx_sequence_masked:
                raise ScriptError("sequence number too small")
            continue

        # BRAIN DAMAGE -- does it always get down here for each verify op? I think not
        if opcode in VERIFY_OPS:
            v = stack.pop()
            if not bool_from_script_bytes(v):
                raise ScriptError("VERIFY failed at %d" % (pc-1), errno.VERIFY)

    if len(if_condition_stack):
        raise ScriptError("missing ENDIF", errno.UNBALANCED_CONDITIONAL)

    if len(stack) + len(altstack) > 1000:
        raise ScriptError("stack has > 1000 items", errno.STACK_SIZE)


def check_script_push_only(script):
    pc = 0
    while pc < len(script):
        opcode, data, pc = get_opcode(script, pc)
        if opcode > opcodes.OP_16:
            raise ScriptError("signature has non-push opcodes", errno.SIG_PUSHONLY)


def is_pay_to_script_hash(script_public_key):
    return (len(script_public_key) == 23 and byte_to_int(script_public_key[0]) == opcodes.OP_HASH160 and
            byte_to_int(script_public_key[-1]) == opcodes.OP_EQUAL)


def witness_program_version(script):
    l = len(script)
    if l < 4 or l > 42:
        return None
    first_opcode = byte_to_int(script[0])
    if byte_to_int(script[1]) + 2 != l:
        return None
    if first_opcode == opcodes.OP_0:
        return 0
    if opcodes.OP_1 <= first_opcode <= opcodes.OP_16:
        return first_opcode - opcodes.OP_1 + 1
    return None


def check_witness_program(
        witness, version, script_signature, flags, signature_for_hash_type_f,
        lock_time, expected_hash_type, traceback_f, tx_sequence, tx_version):
    if version == 0:
        l = len(script_signature)
        if l == 32:
            if len(witness) == 0:
                raise ScriptError("witness program empty", errno.WITNESS_PROGRAM_WITNESS_EMPTY)
            script_public_key = witness[-1]
            stack = Stack(witness[:-1])
            if sha256(script_public_key).digest() != script_signature:
                raise ScriptError("witness program mismatch", errno.WITNESS_PROGRAM_MISMATCH)
        elif l == 20:
            # special case for pay-to-pubkeyhash; signature + pubkey in witness
            if len(witness) != 2:
                raise ScriptError("witness program mismatch", errno.WITNESS_PROGRAM_MISMATCH)
            # "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % b2h(script_signature))
            script_public_key = b'v\xa9' + bin_script([script_signature]) + b'\x88\xac'
            stack = Stack(witness)
        else:
            raise ScriptError("witness program wrong length", errno.WITNESS_PROGRAM_WRONG_LENGTH)
    elif flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
        raise ScriptError(
            "this version witness program not yet supported", errno.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
    else:
        return

    for s in stack:
        if len(s) > 520:
            raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)

    eval_script(script_public_key, signature_for_hash_type_f.witness, lock_time, expected_hash_type,
                stack, traceback_f=traceback_f, flags=flags, is_signature=True,
                tx_sequence=tx_sequence, tx_version=tx_version)

    if len(stack) == 0 or not bool_from_script_bytes(stack[-1]):
        raise ScriptError("eval false", errno.EVAL_FALSE)

    if len(stack) != 1:
        raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)


def check_script(script_signature, script_public_key, signature_for_hash_type_f, lock_time,
                 flags, expected_hash_type, traceback_f, witness, tx_sequence, tx_version):
    had_witness = False
    stack = Stack()

    is_p2h = is_pay_to_script_hash(script_public_key)

    if flags is None:
        flags = VERIFY_P2SH | VERIFY_WITNESS

    if flags & VERIFY_SIGPUSHONLY:
        check_script_push_only(script_signature)

    # never use VERIFY_MINIMALIF or VERIFY_WITNESS_PUBKEYTYPE unless we're in segwit
    witness_flags = flags
    flags &= ~(VERIFY_MINIMALIF | VERIFY_WITNESS_PUBKEYTYPE)

    eval_script(script_signature, signature_for_hash_type_f, lock_time,
                expected_hash_type, stack, traceback_f=traceback_f, flags=flags,
                is_signature=True, tx_sequence=tx_sequence, tx_version=tx_version)

    if is_p2h and (flags & VERIFY_P2SH):
        signatures, alt_script_public_key = stack[:-1], stack[-1]
        alt_script_signature = bin_script(signatures)

    eval_script(script_public_key, signature_for_hash_type_f, lock_time,
                expected_hash_type, stack, traceback_f=traceback_f, flags=flags,
                is_signature=False, tx_sequence=tx_sequence, tx_version=tx_version)

    if len(stack) == 0 or not bool_from_script_bytes(stack[-1]):
        raise ScriptError("eval false", errno.EVAL_FALSE)

    if flags & VERIFY_WITNESS:
        witness_version = witness_program_version(script_public_key)
        if witness_version is not None:
            had_witness = True
            witness_program = script_public_key[2:]
            if len(script_signature) > 0:
                err = errno.WITNESS_MALLEATED if flags & VERIFY_P2SH else errno.WITNESS_MALLEATED_P2SH
                raise ScriptError("script sig is not blank on segwit input", err)
            check_witness_program(
                witness, witness_version, witness_program, witness_flags,
                signature_for_hash_type_f, lock_time, expected_hash_type,
                traceback_f, tx_sequence, tx_version)
            stack = stack[-1:]

    if is_p2h and bool_from_script_bytes(stack[-1]) and (flags & VERIFY_P2SH):
        check_script_push_only(script_signature)
        check_script(
            alt_script_signature, alt_script_public_key, signature_for_hash_type_f, lock_time,
            witness_flags & ~VERIFY_P2SH, expected_hash_type=expected_hash_type,
            traceback_f=traceback_f, witness=witness, tx_sequence=tx_sequence, tx_version=tx_version)
        return

    if (flags & VERIFY_WITNESS) and not had_witness and len(witness) > 0:
        raise ScriptError("witness unexpected", errno.WITNESS_UNEXPECTED)

    if flags & VERIFY_CLEANSTACK and len(stack) != 1:
        raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

    if len(stack) == 0 or not bool_from_script_bytes(stack[-1]):
        raise ScriptError("eval false", errno.EVAL_FALSE)


def verify_script(script_signature, script_public_key, signature_for_hash_type_f, lock_time,
                  flags=None, expected_hash_type=None, traceback_f=None, witness=(),
                  tx_sequence=None, tx_version=None):
    try:
        check_script(
            script_signature, script_public_key, signature_for_hash_type_f, lock_time,
            flags, expected_hash_type, traceback_f, witness, tx_sequence, tx_version)
    except ScriptError:
        return False
    return True
