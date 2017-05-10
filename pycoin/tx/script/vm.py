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


from ...intbytes import byte2int, indexbytes
from .flags import (
    VERIFY_P2SH, VERIFY_SIGPUSHONLY, VERIFY_CLEANSTACK,
    VERIFY_WITNESS, VERIFY_MINIMALIF, VERIFY_WITNESS_PUBKEYTYPE
)

from . import errno
from . import opcodes
from . import ScriptError
from .Stack import Stack
from .eval_script import eval_script
from .segwit import check_witness

from .tools import get_opcode, bin_script, bool_from_script_bytes


def check_script_push_only(script):
    pc = 0
    while pc < len(script):
        opcode, data, pc = get_opcode(script, pc)
        if opcode > opcodes.OP_16:
            raise ScriptError("signature has non-push opcodes", errno.SIG_PUSHONLY)


def is_pay_to_script_hash(script_public_key):
    return (len(script_public_key) == 23 and byte2int(script_public_key) == opcodes.OP_HASH160 and
            indexbytes(script_public_key, -1) == opcodes.OP_EQUAL)


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
        had_witness = check_witness(stack, script_public_key, script_signature, witness, witness_flags,
                                    signature_for_hash_type_f, lock_time, expected_hash_type, traceback_f,
                                    tx_sequence, tx_version)

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
