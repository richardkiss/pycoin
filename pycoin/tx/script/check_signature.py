# -*- coding: utf-8 -*-
"""
Parse, stream, create, sign and verify Bitcoin transactions as Tx structures.


The MIT License (MIT)

Copyright (c) 2015 by Richard Kiss

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

from ... import ecdsa
from ...encoding import sec_to_public_pair, EncodingError
from ...intbytes import int_from_bytes

from . import der
from . import ScriptError

from .microcode import VCH_TRUE, VCH_FALSE
from .tools import bin_script, delete_subscript


def parse_signature_blob(sig_blob):
    sig_pair = der.sigdecode_der(sig_blob[:-1], use_broken_open_ssl_mechanism=True)
    signature_type = ord(sig_blob[-1:])
    return sig_pair, signature_type


def op_checksig(stack, signature_for_hash_type_f, expected_hash_type, tmp_script):
    public_pair = sec_to_public_pair(stack.pop())
    sig_blob = stack.pop()
    try:
        sig_pair, signature_type = parse_signature_blob(sig_blob)
    except der.UnexpectedDER:
        stack.append(VCH_FALSE)
        return

    if expected_hash_type not in (None, signature_type):
        raise ScriptError("wrong hash type")

    # Drop the signature, since there's no way for a signature to sign itself
    # see: Bitcoin Core/script/interpreter.cpp::EvalScript()
    tmp_script = delete_subscript(tmp_script, bin_script([sig_blob]))

    signature_hash = signature_for_hash_type_f(signature_type, script=tmp_script)

    if ecdsa.verify(ecdsa.generator_secp256k1, public_pair, signature_hash, sig_pair):
        stack.append(VCH_TRUE)
    else:
        stack.append(VCH_FALSE)


def op_checkmultisig(stack, signature_for_hash_type_f, expected_hash_type, tmp_script):
    key_count = int_from_bytes(stack.pop())
    public_pairs = []
    for i in range(key_count):
        the_sec = stack.pop()
        try:
            public_pairs.append(sec_to_public_pair(the_sec))
        except EncodingError:
            # we must ignore badly encoded public pairs
            # the transaction 70c4e749f2b8b907875d1483ae43e8a6790b0c8397bbb33682e3602617f9a77a
            # is in a block and requires this hack
            pass

    signature_count = int_from_bytes(stack.pop())
    sig_blobs = []
    for i in range(signature_count):
        sig_blobs.append(stack.pop())

    # check that we have the required hack 00 byte
    if stack != [b'\x00']:
        stack.append(VCH_FALSE)
        return

    # remove the 0 byte hack for pay to script hash
    stack.pop()

    # Drop the signatures, since there's no way for a signature to sign itself
    for sig_blob in sig_blobs:
        tmp_script = delete_subscript(tmp_script, bin_script([sig_blob]))

    sig_ok = VCH_TRUE
    for sig_blob in sig_blobs:
        try:
            sig_pair, signature_type = parse_signature_blob(sig_blob)
        except der.UnexpectedDER:
            sig_ok = VCH_FALSE
            break
        signature_hash = signature_for_hash_type_f(signature_type, script=tmp_script)

        ppp = ecdsa.possible_public_pairs_for_signature(
            ecdsa.generator_secp256k1, signature_hash, sig_pair)

        ppp.intersection_update(public_pairs)
        if len(ppp) == 0:
            sig_ok = VCH_FALSE
            break

        matching_pair = ppp.pop()
        idx = public_pairs.index(matching_pair)
        # The exact order of pubkey/signature evaluation
        # is important for consensus.  If someday it will
        # no longer matter, just replace the line below with:
        # public_pairs = public_pairs[:idx] + public_pairs[idx+1:]
        public_pairs = public_pairs[idx+1:]

    stack.append(sig_ok)
