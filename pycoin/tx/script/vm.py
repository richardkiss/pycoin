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
import logging

from hashlib import sha256

from ...intbytes import byte_to_int, int_to_bytes

from . import opcodes
from . import ScriptError

from .check_signature import op_checksig, op_checkmultisig
from .flags import (
    VERIFY_P2SH, VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_MINIMALDATA,
    VERIFY_SIGPUSHONLY, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CLEANSTACK,
    # VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_WITNESS, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
)
from .microcode import MICROCODE_LOOKUP
from .tools import get_opcode, bin_script, bool_from_script_bytes, int_from_script_bytes


logger = logging.getLogger(__name__)

VERIFY_OPS = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_NUMEQUALVERIFY OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_VERIFY OP_CHECKMULTISIGVERIFY".split())))

INVALID_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_INVERT OP_AND OP_OR OP_XOR OP_2MUL OP_2DIV OP_MUL "
    "OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT OP_VERIF OP_VERNOTIF".split())))

NOP_SET = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_NOP1 OP_NOP3 OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10".split())))


class Stack(list):
    def pop(self, *args, **kwargs):
        try:
            return super(Stack, self).pop(*args, **kwargs)
        except IndexError:
            raise ScriptError("pop from empty stack")

    def __getitem__(self, *args, **kwargs):
        try:
            return super(Stack, self).__getitem__(*args, **kwargs)
        except IndexError:
            raise ScriptError("getitem out of range")


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
    raise ScriptError("not minimal push of %s" % repr(data))


def eval_script(script, signature_for_hash_type_f, lock_time, expected_hash_type=None, stack=[],
                disallow_long_scripts=True, traceback_f=None, is_signature=False, flags=0):
    altstack = Stack()
    if disallow_long_scripts and len(script) > 10000:
        return False

    pc = 0
    begin_code_hash = pc
    if_condition_stack = []
    op_count = 0
    require_minimal = flags & VERIFY_MINIMALDATA

    try:
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
                    raise ScriptError("script contains too many operations")

            if len(stack) + len(altstack) > 1000:
                raise ScriptError("stack has > 1000 items")

            if opcode in INVALID_OPCODE_VALUES:
                raise ScriptError("invalid opcode %s at %d" % (
                        opcodes.INT_TO_OPCODE.get(opcode, hex(opcode)), pc-1))

            if data and len(data) > 520 and disallow_long_scripts:
                raise ScriptError("pushing too much data onto stack")

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
                    v = bool_from_script_bytes(stack.pop())
                if opcode == opcodes.OP_NOTIF:
                    v = not v
                if_condition_stack.append(v)
                continue

            if opcode > 76 and opcode not in opcodes.INT_TO_OPCODE:
                raise ScriptError("invalid opcode %s at %d" % (
                        opcodes.INT_TO_OPCODE.get(opcode, hex(opcode)), pc-1))

            if (flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS) and opcode in NOP_SET:
                raise ScriptError("discouraging nops")

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
                        raise ScriptError("VERIFY failed at %d" % (pc-1))
                continue

            if opcode == opcodes.OP_TOALTSTACK:
                altstack.append(stack.pop())
                continue

            if opcode == opcodes.OP_FROMALTSTACK:
                stack.append(altstack.pop())
                continue

            if opcode == opcodes.OP_1NEGATE:
                stack.append(b'\x81')
                continue

            if opcode > opcodes.OP_1NEGATE and opcode <= opcodes.OP_16:
                stack.append(int_to_bytes(opcode + 1 - opcodes.OP_1))
                continue

            if opcode in (opcodes.OP_ELSE, opcodes.OP_ENDIF):
                raise ScriptError("%s without OP_IF" % opcodes.INT_TO_OPCODE[opcode])

            if opcode in (opcodes.OP_CHECKSIG, opcodes.OP_CHECKSIGVERIFY):
                # Subset of script starting at the most recent codeseparator
                op_checksig(stack, signature_for_hash_type_f, expected_hash_type, script[begin_code_hash:],
                            flags)
                if opcode == opcodes.OP_CHECKSIGVERIFY:
                    if not bool_from_script_bytes(stack.pop()):
                        raise ScriptError("VERIFY failed at %d" % (pc-1))
                continue

            if opcode in (opcodes.OP_CHECKMULTISIG, opcodes.OP_CHECKMULTISIGVERIFY):
                # Subset of script starting at the most recent codeseparator
                n_ops = op_checkmultisig(
                    stack, signature_for_hash_type_f, expected_hash_type, script[begin_code_hash:], flags)
                op_count += n_ops
                if op_count > 201:
                    raise ScriptError("script contains too many operations")

            if opcode == opcodes.OP_CHECKLOCKTIMEVERIFY:
                if not (flags & VERIFY_CHECKLOCKTIMEVERIFY):
                    if (flags & VERIFY_DISCOURAGE_UPGRADABLE_NOPS):
                        raise ScriptError("discouraging nops")
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

            # BRAIN DAMAGE -- does it always get down here for each verify op? I think not
            if opcode in VERIFY_OPS:
                v = stack.pop()
                if not bool_from_script_bytes(v):
                    raise ScriptError("VERIFY failed at %d" % pc-1)

    except Exception:
        logger.exception("script failed for unknown reason")
        raise

    if len(if_condition_stack):
        raise ScriptError("missing ENDIF")

    if len(stack) + len(altstack) > 1000:
        raise ScriptError("stack has > 1000 items")

    return len(stack) != 0


def check_script_push_only(script):
    pc = 0
    while pc < len(script):
        opcode, data, pc = get_opcode(script, pc)
        if opcode > opcodes.OP_16:
            raise ScriptError("signature has non-push opcodes")


def is_pay_to_script_hash(script_public_key):
    return (len(script_public_key) == 23 and byte_to_int(script_public_key[0]) == opcodes.OP_HASH160 and
            byte_to_int(script_public_key[-1]) == opcodes.OP_EQUAL)


def witness_program_version(script):
    l = len(script)
    if l < 4 or l > 42:
        return None
    first_opcode = byte_to_int(script[0])
    if first_opcode == opcodes.OP_0:
        return 0
    if opcodes.OP_1 <= first_opcode <= opcodes.OP_16:
        return first_opcode - opcodes.OP_1 + 1
    return None


def verify_witness_program(
        witness, version, script_signature, flags, signature_for_hash_type_f,
        lock_time, expected_hash_type, traceback_f):
    if version == 0:
        l = len(script_signature)
        if l == 32:
            if len(witness) == 0:
                raise ScriptError("witness program empty")
            script_public_key = witness[-1]
            stack = list(witness[:-1])
            if sha256(script_public_key).digest() != script_signature:
                raise ScriptError("witness program mismatch")
        elif l == 20:
            # special case for pay-to-pubkeyhash; signature + pubkey in witness
            if len(witness) != 2:
                raise ScriptError("witness program mismatch")
            # "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % b2h(script_signature))
            script_public_key = b'v\xa9' + bin_script([script_signature]) + b'\x88\xac'
            stack = list(witness)
        else:
            raise ScriptError("witness program wrong length")
    elif flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
        raise ScriptError("this version witness program not yet supported")
    else:
        return True

    for s in stack:
        if len(s) > 520:
            raise ScriptError("pushing too much data onto stack")

    eval_script(script_public_key, signature_for_hash_type_f.witness, lock_time, expected_hash_type,
                stack, traceback_f=traceback_f, flags=flags, is_signature=True)

    return len(stack) > 0 and bool_from_script_bytes(stack[-1])


def verify_script(script_signature, script_public_key, signature_for_hash_type_f, lock_time,
                  flags=None, expected_hash_type=None, traceback_f=None, witness=()):
    stack = Stack()

    is_p2h = is_pay_to_script_hash(script_public_key)

    if flags is None:
        flags = VERIFY_P2SH | VERIFY_WITNESS

    if flags & VERIFY_SIGPUSHONLY:
        check_script_push_only(script_signature)

    try:
        eval_script(script_signature, signature_for_hash_type_f, lock_time, expected_hash_type,
                    stack, traceback_f=traceback_f, flags=flags, is_signature=True)

        if is_p2h and (flags & VERIFY_P2SH):
            signatures, alt_script_public_key = stack[:-1], stack[-1]
            alt_script_signature = bin_script(signatures)

        eval_script(script_public_key, signature_for_hash_type_f, lock_time, expected_hash_type,
                    stack, traceback_f=traceback_f, flags=flags, is_signature=False)

        if len(stack) == 0 or not bool_from_script_bytes(stack[-1]):
            return False

        if flags & VERIFY_WITNESS:
            witness_version = witness_program_version(script_public_key)
            if witness_version is not None:
                witness_program = script_public_key[2:]
                if len(script_signature) > 0:
                    raise ScriptError("script sig is not blank on segwit input")
                if not verify_witness_program(
                        witness, witness_version, witness_program, flags,
                        signature_for_hash_type_f, lock_time, expected_hash_type,
                        traceback_f):
                    return False
                return True

    except ScriptError:
        return False

    if is_p2h and bool_from_script_bytes(stack[-1]) and (flags & VERIFY_P2SH):
        check_script_push_only(script_signature)
        return verify_script(alt_script_signature, alt_script_public_key, signature_for_hash_type_f,
                             lock_time, flags & ~VERIFY_P2SH, expected_hash_type=expected_hash_type,
                             traceback_f=traceback_f, witness=witness)

    if flags & VERIFY_CLEANSTACK and len(stack) != 1:
        raise ScriptError("stack not clean after evaulation")

    return len(stack) > 0 and bool_from_script_bytes(stack[-1])
