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


def sig_blob_matches(sig_blobs, public_pairs, tmp_script, signature_for_hash_type_f, strict_checks=False):
    """
    sig_blobs: signature blobs
    public_pairs: a list of public pairs that might be valid
    tmp_script: the script as of the last code separator
    signature_for_hash_type_f: signature_for_hash_type_f
    strict_checks: if True, we may exit early if one of the sig_blobs is incorrect or misplaced. Used
                   for checking a supposedly validated transaction. A -1 indicates no match.

    Returns a list of indices into public_pairs. If strict_checks is True, it may return early.
    If strict_checks isn't long enough or contains a -1, the signature is not valid.
    """

    # Drop the signatures, since there's no way for a signature to sign itself
    for sig_blob in sig_blobs:
        tmp_script = delete_subscript(tmp_script, bin_script([sig_blob]))

    sig_cache = {}
    sig_blob_indices = []
    for sig_blob in sig_blobs:
        public_pair_index = -1
        try:
            sig_pair, signature_type = parse_signature_blob(sig_blob)
        except der.UnexpectedDER:
            if strict_checks:
                return sig_blob_indices

        if signature_type not in sig_cache:
            sig_cache[signature_type] = signature_for_hash_type_f(signature_type, script=tmp_script)

        ppp = ecdsa.possible_public_pairs_for_signature(
            ecdsa.generator_secp256k1, sig_cache[signature_type], sig_pair)

        if len(ppp) > 0:
            for idx, pp in enumerate(public_pairs):
                if idx in sig_blob_indices:
                    continue
                if pp in ppp:
                    sig_blob_indices.append(idx)
                    break
            else:
                if strict_checks:
                    return sig_blob_indices
                sig_blob_indices.append(-1)

            if len(sig_blob_indices) > 1 and strict_checks:
                # look for signatures in the wrong order
                if sig_blob_indices[-1] <= sig_blob_indices[-2]:
                    return sig_blob_indices
        else:
            if strict_checks:
                return sig_blob_indices
    return sig_blob_indices


def op_checkmultisig(stack, signature_for_hash_type_f, expected_hash_type, tmp_script, verify_null_dummy=True):
    pub_count = int_from_bytes(stack.pop())
    pub_secs = [stack.pop() for _ in range(pub_count)]
    sig_count = int_from_bytes(stack.pop())
    sig_blobs = [stack.pop() for _ in range(sig_count)]
    extra_stack_item_bug = stack.pop()

    # Previously, interpreters did not care what this value was; now (to
    # avoid malleability) most enforce that it must be OP_0
    if verify_null_dummy and extra_stack_item_bug != b'\x00':
        stack.append(VCH_FALSE)
        raise ScriptError("Dummy CHECKMULTISIG argument must be zero")

    k = s = 0
    match_found = True
    sig_hash_cache = {}
    sig_ok = VCH_TRUE

    while s < sig_count and (sig_count - s <= pub_count - k):
        try:
            pub_pair = sec_to_public_pair(pub_secs[k])
        except EncodingError:
            # we must ignore badly encoded public pairs
            # the transaction 70c4e749f2b8b907875d1483ae43e8a6790b0c8397bbb33682e3602617f9a77a
            # is in a block and requires this hack
            k += 1
            continue
        else:
            k += 1
        if match_found:
            sig_pair, sig_type = parse_signature_blob(sig_blobs[s])
            try:
                sig_hash = sig_hash_cache[(sig_type, tmp_script)]
            except KeyError:
                sig_hash = sig_hash_cache[(sig_type, tmp_script)] = signature_for_hash_type_f(sig_type, tmp_script)
        match_found = ecdsa.verify(ecdsa.generator_secp256k1, pub_pair, sig_hash, sig_pair)
        if match_found:
            s += 1

    if s < sig_count:
        sig_ok = VCH_FALSE
    stack.append(sig_ok)

    #---- BEGIN PRIOR IMPLEMENTATION ----

    # key_count = int_from_bytes(stack.pop())
    # public_pairs = []
    # for i in range(key_count):
    #     the_sec = stack.pop()
    #     try:
    #         public_pairs.append(sec_to_public_pair(the_sec))
    #     except EncodingError:
    #         # we must ignore badly encoded public pairs
    #         # the transaction 70c4e749f2b8b907875d1483ae43e8a6790b0c8397bbb33682e3602617f9a77a
    #         # is in a block and requires this hack
    #         pass

    # signature_count = int_from_bytes(stack.pop())
    # sig_blobs = []
    # for i in range(signature_count):
    #     sig_blobs.append(stack.pop())

    # # - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - =
    # # <COMMENTARY>I think this is too restrictive. Enforcing that the
    # # *entire* stack must be [b'\x00'] may cause evaluation to fail for
    # # otherwise valid (but non-standard) scripts. It's probably better to
    # # pop the top value and make sure it's equal to b'\x00' (see, e.g.,
    # # above).</COMMENTARY>
    # # - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - =
    # # check that we have the required hack 00 byte
    # if stack != [b'\x00']:
    #     stack.append(VCH_FALSE)
    #     return

    # # remove the 0 byte hack for pay to script hash
    # stack.pop()

    # # - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - =
    # # <COMMENTARY>In an m-of-n situation, I *think* this approach ensures
    # # that ecdsa.verify() is called at least 2m times (because of
    # # ecdsa.possible_public_pairs_for_signature). Where 2m < n, this will
    # # be more efficient, but for 2m >= n, then this will suffer. If
    # # ecdsa.verify is called on a per-signature basis, it will be called
    # # at least m times and at most n. ecdsa.verify() has proven to be an
    # # expensive operation, so optimizing seems to be
    # # appropriate.</COMMENTARY>
    # # - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - = - =
    # sig_blob_indices = sig_blob_matches(
    #     sig_blobs, public_pairs, tmp_script, signature_for_hash_type_f, strict_checks=True)

    # sig_ok = VCH_FALSE
    # if -1 not in sig_blob_indices and len(sig_blob_indices) == len(sig_blobs):
    #     # bitcoin requires the signatures to be in the same order as the public keys
    #     # so let's make sure the indices are strictly increasing
    #     for i in range(len(sig_blob_indices) - 1):
    #         if sig_blob_indices[i] >= sig_blob_indices[i+1]:
    #             break
    #     else:
    #         sig_ok = VCH_TRUE

    # stack.append(sig_ok)

    #----- END PRIOR IMPLEMENTATION -----
