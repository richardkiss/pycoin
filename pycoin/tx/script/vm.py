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

from ... import ecdsa
from ...encoding import sec_to_public_pair, EncodingError

from . import der
from . import opcodes
from . import ScriptError

from .microcode import MICROCODE_LOOKUP, VCH_TRUE, make_bool
from .tools import get_opcode

VERIFY_OPS = frozenset((opcodes.OPCODE_TO_INT[s] for s in "OP_NUMEQUALVERIFY OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_VERIFY OP_CHECKMULTISIGVERIFY".split()))

INVALID_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in "OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_INVERT OP_AND OP_OR OP_XOR OP_2MUL OP_2DIV OP_MUL OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT".split()))

def check_signature(signature_for_hash_type_f, public_key_blob, sig_blob, expected_hash_type=None):
    """Ensure the given transaction has the correct signature. Invoked by the VM.
    Adapted from official Bitcoin-QT client.

    signature_for_hash_type_f: a function returning the signature hash of the transaction
        being verified given a hash type
    public_key_blob: the blob representing the SEC-encoded public pair
    sig_blob: the blob representing the DER-encoded signature
    expected_hash_type: expected signature_type (or 0 for wild card)
    """
    signature_type = ord(sig_blob[-1:])
    sig_pair = der.sigdecode_der(sig_blob[:-1])
    if expected_hash_type not in (None, signature_type):
        raise ScriptError("wrong hash type")
    try:
        public_pair = sec_to_public_pair(public_key_blob)
        signature_hash = signature_for_hash_type_f(signature_type)
        v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, signature_hash, sig_pair)
    except EncodingError:
        v = 0
    return make_bool(v)

def eval_script(script, signature_for_hash_type_f, expected_hash_type=None, stack=[]):
    altstack = []
    if len(script) > 10000:
        return False

    pc = 0
    begin_code_hash = pc
    if_condition = None # or True or False
    op_count = 0
    # TODO: set op_count

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
                stack.append(opcode + 1 - opcodes.OP_1)
                continue

            if opcode in (opcodes.OP_ELSE, opcodes.OP_ENDIF):
                raise ScriptError("%s without OP_IF" % opcodes.INT_TO_OPCODE[opcode])

            if opcode in (opcodes.OP_CHECKSIG, opcodes.OP_CHECKSIGVERIFY):
                public_key_blob = stack.pop()
                sig_blob = stack.pop()
                v = check_signature(
                    signature_for_hash_type_f, public_key_blob, sig_blob, expected_hash_type)
                stack.append(v)
                if opcode == opcodes.OP_CHECKSIGVERIFY:
                    if stack.pop() != VCH_TRUE:
                        raise ScriptError("VERIFY failed at %d" % pc-1)
                continue

            if opcode == opcodes.OP_CHECKMULTISIG:
                key_count = stack.pop()
                public_key_blobs = []
                for i in range(key_count):
                    public_key_blobs.append(stack.pop())

                signature_count = stack.pop()
                sig_blobs = []
                for i in range(signature_count):
                    sig_blobs.append(stack.pop())

                for sig_blob in sig_blobs:
                    for public_key_blob in public_key_blobs:
                        sig_ok = check_signature(
                            signature_for_hash_type_f, public_key_blob, sig_blob, expected_hash_type)
                        if sig_ok == VCH_TRUE:
                            break
                    if sig_ok != VCH_TRUE:
                        break
                should_be_zero_bug = stack.pop()
                stack.append(sig_ok)
                continue

            # BRAIN DAMAGE -- does it always get down here for each verify op? I think not
            if opcode in VERIFY_OPS:
                v = stack.pop()
                if v != VCH_TRUE:
                    raise ScriptError("VERIFY failed at %d" % pc-1)

            logging.error("can't execute opcode %s", opcode)

    except Exception as ex:
        logging.exception("script failed")

    return len(stack) != 0

def verify_script(script_signature, script_public_key, signature_for_hash_type_f, expected_hash_type=None):
    stack = []

    is_p2h = (len(script_public_key) == 23 and script_public_key[0] == opcodes.OP_HASH160
                and script_public_key[-1] == opcodes.OP_EQUAL)

    if not eval_script(script_signature, signature_for_hash_type_f, expected_hash_type, stack):
        logging.debug("script_signature did not evaluate")
        return False

    if is_p2h:
        signatures, alt_script_public_key = stack[:-1], stack[-1]
        from pycoin.tx.script import tools
        from pycoin import serialize
        def sub(x):
            if x == '00':
                return '0'
            return x
        s1 = [sub(serialize.b2h(s)) for s in signatures]
        alt_script_signature = tools.compile(" ".join(s1))

    if not eval_script(script_public_key, signature_for_hash_type_f, expected_hash_type, stack):
        logging.debug("script_public_key did not evaluate")
        return False

    if is_p2h and stack[-1] == VCH_TRUE:
        return verify_script(alt_script_signature, alt_script_public_key,
                             signature_for_hash_type_f, expected_hash_type=expected_hash_type)

    return stack[-1] == VCH_TRUE
