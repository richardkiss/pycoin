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
from ...intbytes import byte2int, indexbytes, iterbytes

from . import der
from . import ScriptError
from . import errno

from .flags import (
    VERIFY_NULLDUMMY, VERIFY_NULLFAIL, VERIFY_STRICTENC, VERIFY_MINIMALDATA,
    VERIFY_DERSIG, VERIFY_LOW_S, VERIFY_WITNESS_PUBKEYTYPE
)

from .microcode import VCH_TRUE, VCH_FALSE
from .tools import bin_script, delete_subscript, int_from_script_bytes


def _check_valid_signature_1(sig):
    ls = len(sig)
    if ls < 9 or ls > 73:
        raise ScriptError("bad signature size", errno.SIG_DER)
    if sig[0] != 0x30:
        raise ScriptError("bad signature byte 0", errno.SIG_DER)
    if sig[1] != ls - 3:
        raise ScriptError("signature size wrong", errno.SIG_DER)
    r_len = sig[3]
    if 5 + r_len >= ls:
        raise ScriptError("r length exceed signature size", errno.SIG_DER)


def _check_valid_signature_2(sig):
    ls = len(sig)
    r_len = sig[3]
    s_len = sig[5 + r_len]
    if r_len + s_len + 7 != ls:
        raise ScriptError("r and s size exceed signature size", errno.SIG_DER)
    if sig[2] != 2:
        raise ScriptError("R value region does not start with 0x02", errno.SIG_DER)
    if r_len == 0:
        raise ScriptError("zero-length R value", errno.SIG_DER)
    if sig[4] & 0x80:
        raise ScriptError("sig R value not allowed to be negative", errno.SIG_DER)
    if r_len > 1 and sig[4] == 0 and not (sig[5] & 0x80):
        raise ScriptError(
            "R value can't have leading 0 byte unless doing so would make it negative", errno.SIG_DER)
    if sig[r_len + 4] != 2:
        raise ScriptError("S value region does not start with 0x02", errno.SIG_DER)
    if s_len == 0:
        raise ScriptError("zero-length S value", errno.SIG_DER)
    if sig[r_len + 6] & 0x80:
        raise ScriptError("negative S values not allowed", errno.SIG_DER)
    if s_len > 1 and sig[r_len + 6] == 0 and not (sig[r_len + 7] & 0x80):
        raise ScriptError(
            "S value can't have leading 0 byte unless doing so would make it negative", errno.SIG_DER)


def check_valid_signature(sig):
    # ported from bitcoind src/script/interpreter.cpp IsValidSignatureEncoding
    sig = [s for s in iterbytes(sig)]
    _check_valid_signature_1(sig)
    _check_valid_signature_2(sig)


def check_low_der_signature(sig_pair):
    # IsLowDERSignature
    r, s = sig_pair
    hi_s = ecdsa.generator_secp256k1.curve().p() - s
    if hi_s < s:
        raise ScriptError("signature has high S value", errno.SIG_HIGH_S)


def check_defined_hashtype_signature(sig):
    # IsDefinedHashtypeSignature
    from pycoin.tx.Tx import SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY
    if len(sig) == 0:
        raise ScriptError("signature is length 0")
    hash_type = indexbytes(sig, -1) & (~SIGHASH_ANYONECANPAY)
    if hash_type < SIGHASH_ALL or hash_type > SIGHASH_SINGLE:
        raise ScriptError("bad hash type after signature", errno.SIG_HASHTYPE)


def parse_signature_blob(sig_blob, flags=0):
    if len(sig_blob) == 0:
        raise ValueError("empty sig_blob")
    if flags & (VERIFY_DERSIG | VERIFY_LOW_S | VERIFY_STRICTENC):
        check_valid_signature(sig_blob)
    if flags & VERIFY_STRICTENC:
        check_defined_hashtype_signature(sig_blob)
    sig_pair = der.sigdecode_der(sig_blob[:-1], use_broken_open_ssl_mechanism=True)
    signature_type = ord(sig_blob[-1:])
    if flags & VERIFY_LOW_S:
        check_low_der_signature(sig_pair)
    return sig_pair, signature_type


def check_public_key_encoding(blob):
    lb = len(blob)
    if lb >= 33:
        fb = byte2int(blob)
        if fb == 4:
            if lb == 65:
                return
        elif fb in (2, 3):
            if lb == 33:
                return
    raise ScriptError("invalid public key blob", errno.PUBKEYTYPE)


def op_checksig(stack, signature_for_hash_type_f, expected_hash_type, tmp_script, flags):
    try:
        pair_blob = stack.pop()
        sig_blob = stack.pop()
        verify_strict = not not (flags & VERIFY_STRICTENC)
        # if verify_strict flag is set, we fail the script immediately on bad encoding
        if verify_strict:
            check_public_key_encoding(pair_blob)
        if flags & VERIFY_WITNESS_PUBKEYTYPE:
            if byte2int(pair_blob) not in (2, 3) or len(pair_blob) != 33:
                raise ScriptError("uncompressed key in witness", errno.WITNESS_PUBKEYTYPE)
        sig_pair, signature_type = parse_signature_blob(sig_blob, flags)
        public_pair = sec_to_public_pair(pair_blob, strict=verify_strict)
    except (der.UnexpectedDER, ValueError, EncodingError):
        stack.append(VCH_FALSE)
        return

    if expected_hash_type not in (None, signature_type):
        raise ScriptError("wrong hash type")

    # Drop the signature, since there's no way for a signature to sign itself
    # see: Bitcoin Core/script/interpreter.cpp::EvalScript()
    if not getattr(signature_for_hash_type_f, "skip_delete", False):
        tmp_script = delete_subscript(tmp_script, bin_script([sig_blob]))

    signature_hash = signature_for_hash_type_f(signature_type, script=tmp_script)

    if ecdsa.verify(ecdsa.generator_secp256k1, public_pair, signature_hash, sig_pair):
        stack.append(VCH_TRUE)
    else:
        if flags & VERIFY_NULLFAIL:
            if len(sig_blob) > 0:
                raise ScriptError("bad signature not NULL", errno.NULLFAIL)
        stack.append(VCH_FALSE)


def sig_blob_matches(sig_blobs, public_pair_blobs, tmp_script, signature_for_hash_type_f,
                     flags, exit_early=False):
    """
    sig_blobs: signature blobs
    public_pair_blobs: a list of public pair blobs
    tmp_script: the script as of the last code separator
    signature_for_hash_type_f: signature_for_hash_type_f
    flags: verification flags to apply
    exit_early: if True, we may exit early if one of the sig_blobs is incorrect or misplaced. Used
    for checking a supposedly validated transaction. A -1 indicates no match.

    Returns a list of indices into public_pairs. If exit_early is True, it may return early.
    If sig_blob_indices isn't long enough or contains a -1, the signature is not valid.
    """

    strict_encoding = not not (flags & VERIFY_STRICTENC)

    # Drop the signatures, since there's no way for a signature to sign itself
    if not getattr(signature_for_hash_type_f, "skip_delete", False):
        for sig_blob in sig_blobs:
            tmp_script = delete_subscript(tmp_script, bin_script([sig_blob]))

    sig_cache = {}
    sig_blob_indices = []
    ppb_idx = -1

    while sig_blobs and len(sig_blobs) <= len(public_pair_blobs):
        if exit_early and -1 in sig_blob_indices:
            break
        sig_blob, sig_blobs = sig_blobs[0], sig_blobs[1:]
        try:
            sig_pair, signature_type = parse_signature_blob(sig_blob, flags)
        except (der.UnexpectedDER, ValueError):
            sig_blob_indices.append(-1)
            continue

        if signature_type not in sig_cache:
            sig_cache[signature_type] = signature_for_hash_type_f(signature_type, script=tmp_script)

        try:
            ppp = ecdsa.possible_public_pairs_for_signature(
                ecdsa.generator_secp256k1, sig_cache[signature_type], sig_pair)
        except ecdsa.NoSuchPointError:
            ppp = []

        while len(sig_blobs) < len(public_pair_blobs):
            public_pair_blob, public_pair_blobs = public_pair_blobs[0], public_pair_blobs[1:]
            ppb_idx += 1
            if strict_encoding:
                check_public_key_encoding(public_pair_blob)
            if flags & VERIFY_WITNESS_PUBKEYTYPE:
                if byte2int(public_pair_blob) not in (2, 3) or len(public_pair_blob) != 33:
                    raise ScriptError("uncompressed key in witness", errno.WITNESS_PUBKEYTYPE)
            try:
                public_pair = sec_to_public_pair(public_pair_blob, strict=strict_encoding)
            except EncodingError:
                public_pair = None
            if public_pair in ppp:
                sig_blob_indices.append(ppb_idx)
                break
        else:
            sig_blob_indices.append(-1)
    return sig_blob_indices


def op_checkmultisig(stack, signature_for_hash_type_f, expected_hash_type, tmp_script, flags):
    require_minimal = flags & VERIFY_MINIMALDATA
    key_count = int_from_script_bytes(stack.pop(), require_minimal=require_minimal)
    if key_count < 0 or key_count > 20:
        raise ScriptError("key_count not in range 0 to 20", errno.PUBKEY_COUNT)

    public_pair_blobs = [stack.pop() for _ in range(key_count)]

    signature_count = int_from_script_bytes(stack.pop(), require_minimal=require_minimal)
    if signature_count < 0 or signature_count > key_count:
        raise ScriptError(
            "invalid number of signatures: %d for %d keys" % (signature_count, key_count), errno.SIG_COUNT)

    sig_blobs = [stack.pop() for _ in range(signature_count)]

    # check that we have the required hack 00 byte
    hack_byte = stack.pop()
    if flags & VERIFY_NULLDUMMY and hack_byte != b'':
        raise ScriptError("bad dummy byte in checkmultisig", errno.SIG_NULLDUMMY)

    sig_blob_indices = sig_blob_matches(
        sig_blobs, public_pair_blobs, tmp_script, signature_for_hash_type_f, flags, exit_early=True)

    sig_ok = VCH_FALSE
    if -1 not in sig_blob_indices and len(sig_blob_indices) == len(sig_blobs):
        # bitcoin requires the signatures to be in the same order as the public keys
        # so let's make sure the indices are strictly increasing
        for i in range(len(sig_blob_indices) - 1):
            if sig_blob_indices[i] >= sig_blob_indices[i+1]:
                break
        else:
            sig_ok = VCH_TRUE

    if not sig_ok and flags & VERIFY_NULLFAIL:
        for sig_blob in sig_blobs:
            if len(sig_blob) > 0:
                raise ScriptError("bad signature not NULL", errno.NULLFAIL)

    stack.append(sig_ok)
    return key_count
