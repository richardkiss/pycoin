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

import logging

from ...intbytes import byte_to_int, int_to_bytes

from . import opcodes
from . import ScriptError

from .check_signature import op_checksig, op_checkmultisig
from .microcode import MICROCODE_LOOKUP, VCH_TRUE, VCH_FALSE
from .tools import get_opcode, bin_script

logger = logging.getLogger(__name__)

VERIFY_OPS = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_NUMEQUALVERIFY OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_VERIFY OP_CHECKMULTISIGVERIFY".split())))

INVALID_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in (
    "OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_INVERT OP_AND OP_OR OP_XOR OP_2MUL OP_2DIV OP_MUL "
    "OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT".split())))


def eval_script(script, signature_for_hash_type_f, expected_hash_type=None, stack=[],
                disallow_long_scripts=True):
    altstack = []
    if disallow_long_scripts and len(script) > 10000:
        return False

    pc = 0
    begin_code_hash = pc
    if_condition = None  # or True or False
    # TODO: set op_count
    # op_count = 0

    try:
        while pc < len(script):
            opcode, data, pc = get_opcode(script, pc)
            if len(data) > 0:
                stack.append(data)
                continue

            # deal with if_condition first

            if if_condition is not None:
                # TODO: fix IF (which doesn't properly nest)
                if opcode == opcodes.OP_ELSE:
                    if_condition = not if_condition
                    continue
                if opcode == opcodes.OP_ENDIF:
                    if_condition = None
                    continue
                if not if_condition:
                    continue
            if opcode in (opcodes.OP_IF, opcodes.OP_NOTIF):
                if_condition = (stack.pop() == VCH_TRUE)
                continue

            if opcode == opcodes.OP_CODESEPARATOR:
                begin_code_hash = pc - 1
                continue

            if opcode in INVALID_OPCODE_VALUES:
                raise ScriptError("invalid opcode %s at %d" % (opcodes.INT_TO_OPCODE[opcode], pc-1))

            if opcode in MICROCODE_LOOKUP:
                MICROCODE_LOOKUP[opcode](stack)
                if opcode in VERIFY_OPS:
                    v = stack.pop()
                    if v != VCH_TRUE:
                        raise ScriptError("VERIFY failed at %d" % (pc-1))
                continue

            if opcode == opcodes.OP_TOALTSTACK:
                altstack.append(stack.pop())
                continue

            if opcode == opcodes.OP_FROMALTSTACK:
                stack.append(altstack.pop())
                continue

            if opcode >= opcodes.OP_1NEGATE and opcode <= opcodes.OP_16:
                stack.append(int_to_bytes(opcode + 1 - opcodes.OP_1))
                continue

            if opcode in (opcodes.OP_ELSE, opcodes.OP_ENDIF):
                raise ScriptError("%s without OP_IF" % opcodes.INT_TO_OPCODE[opcode])

            if opcode in (opcodes.OP_CHECKSIG, opcodes.OP_CHECKSIGVERIFY):
                # Subset of script starting at the most recent codeseparator
                op_checksig(stack, signature_for_hash_type_f, expected_hash_type, script[begin_code_hash:])
                if opcode == opcodes.OP_CHECKSIGVERIFY:
                    if stack.pop() != VCH_TRUE:
                        raise ScriptError("VERIFY failed at %d" % (pc-1))
                continue

            if opcode == opcodes.OP_CHECKMULTISIG:
                # Subset of script starting at the most recent codeseparator
                op_checkmultisig(
                    stack, signature_for_hash_type_f, expected_hash_type, script[begin_code_hash:])
                continue

            # BRAIN DAMAGE -- does it always get down here for each verify op? I think not
            if opcode in VERIFY_OPS:
                v = stack.pop()
                if v != VCH_TRUE:
                    raise ScriptError("VERIFY failed at %d" % pc-1)

            logger.error("can't execute opcode %s", opcode)

    except Exception:
        logger.exception("script failed")

    return len(stack) != 0


def verify_script(script_signature, script_public_key, signature_for_hash_type_f, expected_hash_type=None):
    stack = []

    is_p2h = (len(script_public_key) == 23 and byte_to_int(script_public_key[0]) == opcodes.OP_HASH160
              and byte_to_int(script_public_key[-1]) == opcodes.OP_EQUAL)

    if not eval_script(script_signature, signature_for_hash_type_f, expected_hash_type, stack):
        logger.debug("script_signature did not evaluate")
        return False

    if is_p2h:
        signatures, alt_script_public_key = stack[:-1], stack[-1]
        alt_script_signature = bin_script(signatures)

    if not eval_script(script_public_key, signature_for_hash_type_f, expected_hash_type, stack):
        logger.debug("script_public_key did not evaluate")
        return False

    if is_p2h and stack[-1] == VCH_TRUE:
        return verify_script(alt_script_signature, alt_script_public_key,
                             signature_for_hash_type_f, expected_hash_type=expected_hash_type)

    return stack[-1] != VCH_FALSE
