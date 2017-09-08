# -*- coding: utf-8 -*-
"""
Parse, stream, create, sign and verify Bitcoin transactions as Tx structures.


The MIT License (MIT)

Copyright (c) 2017 by Richard Kiss

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


from hashlib import sha256

from ...intbytes import byte2int, indexbytes
from .flags import (
    VERIFY_P2SH, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
)

from . import errno
from . import opcodes
from . import ScriptError
from .Stack import Stack

from .eval_script import eval_script
from .tools import bin_script, bool_from_script_bytes


def witness_program_version(script):
    l = len(script)
    if l < 4 or l > 42:
        return None
    first_opcode = byte2int(script)
    if indexbytes(script, 1) + 2 != l:
        return None
    if first_opcode == opcodes.OP_0:
        return 0
    if opcodes.OP_1 <= first_opcode <= opcodes.OP_16:
        return first_opcode - opcodes.OP_1 + 1
    return None


def check_witness_program_v0(
        witness, script_signature, flags, signature_for_hash_type_f,
        lock_time, expected_hash_type, traceback_f, tx_sequence, tx_version):
    l = len(script_signature)
    if l == 32:
        if len(witness) == 0:
            raise ScriptError("witness program empty", errno.WITNESS_PROGRAM_WITNESS_EMPTY)
        script_public_key = witness[-1]
        if sha256(script_public_key).digest() != script_signature:
            raise ScriptError("witness program mismatch", errno.WITNESS_PROGRAM_MISMATCH)
        stack = Stack(witness[:-1])
    elif l == 20:
        # special case for pay-to-pubkeyhash; signature + pubkey in witness
        if len(witness) != 2:
            raise ScriptError("witness program mismatch", errno.WITNESS_PROGRAM_MISMATCH)
        # "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % b2h(script_signature))
        script_public_key = b'v\xa9' + bin_script([script_signature]) + b'\x88\xac'
        stack = Stack(witness)
    else:
        raise ScriptError("witness program wrong length", errno.WITNESS_PROGRAM_WRONG_LENGTH)
    return stack, script_public_key


def check_witness_program(
        witness, version, script_signature, flags, signature_for_hash_type_f,
        lock_time, expected_hash_type, traceback_f, tx_sequence, tx_version):
    if version == 0:
        stack, script_public_key = check_witness_program_v0(
            witness, script_signature, flags, signature_for_hash_type_f,
            lock_time, expected_hash_type, traceback_f, tx_sequence, tx_version)
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


def check_witness(stack, script_public_key, script_signature, witness, witness_flags, signature_for_hash_type_f,
                  lock_time, expected_hash_type, traceback_f, tx_sequence, tx_version):
    witness_version = witness_program_version(script_public_key)
    had_witness = False
    if witness_version is not None:
        had_witness = True
        witness_program = script_public_key[2:]
        if len(script_signature) > 0:
            err = errno.WITNESS_MALLEATED if witness_flags & VERIFY_P2SH else errno.WITNESS_MALLEATED_P2SH
            raise ScriptError("script sig is not blank on segwit input", err)
        check_witness_program(
            witness, witness_version, witness_program, witness_flags,
            signature_for_hash_type_f, lock_time, expected_hash_type,
            traceback_f, tx_sequence, tx_version)
        stack[:] = stack[-1:]
    return had_witness
