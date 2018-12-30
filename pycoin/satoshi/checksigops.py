from ..encoding.sec import sec_to_public_pair, EncodingError
from ..intbytes import byte2int, indexbytes, iterbytes

from . import der
from . import errno

from .flags import (
    SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
    VERIFY_NULLDUMMY, VERIFY_NULLFAIL, VERIFY_STRICTENC,
    VERIFY_DERSIG, VERIFY_LOW_S, VERIFY_WITNESS_PUBKEYTYPE
)

from pycoin.coins.SolutionChecker import ScriptError


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


def check_low_der_signature(sig_pair, generator):
    # IsLowDERSignature
    r, s = sig_pair
    hi_s = generator.p() - s
    if hi_s < s:
        raise ScriptError("signature has high S value", errno.SIG_HIGH_S)


def check_defined_hashtype_signature(sig):
    # IsDefinedHashtypeSignature
    if len(sig) == 0:
        raise ScriptError("signature is length 0")
    hash_type = indexbytes(sig, -1) & (~SIGHASH_ANYONECANPAY)
    if hash_type < SIGHASH_ALL or hash_type > SIGHASH_SINGLE:
        raise ScriptError("bad hash type after signature", errno.SIG_HASHTYPE)


def parse_signature_blob(sig_blob):
    if len(sig_blob) == 0:
        raise ValueError("empty sig_blob")
    sig_pair = der.sigdecode_der(sig_blob[:-1], use_broken_open_ssl_mechanism=True)
    signature_type = ord(sig_blob[-1:])
    return sig_pair, signature_type


def parse_and_check_signature_blob(sig_blob, flags, vm):
    if len(sig_blob) == 0:
        raise ValueError("empty sig_blob")
    if flags & (VERIFY_DERSIG | VERIFY_LOW_S | VERIFY_STRICTENC):
        check_valid_signature(sig_blob)
    if flags & VERIFY_STRICTENC:
        check_defined_hashtype_signature(sig_blob)
    sig_pair, signature_type = parse_signature_blob(sig_blob)
    if flags & VERIFY_LOW_S:
        generator = vm.generator_for_signature_type(signature_type)
        check_low_der_signature(sig_pair, generator)
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


def checksig(vm, sig_pair, signature_type, pair_blob, blobs_to_delete,
             sighash_cache, verify_witness_pubkeytype, verify_strict):
    generator = vm.generator_for_signature_type(signature_type)
    if verify_strict:
        check_public_key_encoding(pair_blob)
    if verify_witness_pubkeytype:
        if byte2int(pair_blob) not in (2, 3) or len(pair_blob) != 33:
            raise ScriptError("uncompressed key in witness", errno.WITNESS_PUBKEYTYPE)
    try:
        public_pair = sec_to_public_pair(pair_blob, generator, strict=verify_strict)
    except (ValueError, EncodingError):
        return False

    if signature_type not in sighash_cache:
        sighash_cache[signature_type] = vm.signature_for_hash_type_f(signature_type, blobs_to_delete, vm)

    try:
        if generator.verify(public_pair, sighash_cache[signature_type], sig_pair):
            return True
    except ValueError:
        pass
    return False


def checksigs(vm, sig_blobs, public_pair_blobs):
    sig_blobs_remaining = list(sig_blobs)
    flags = vm.flags
    sighash_cache = {}
    verify_witness_pubkeytype = flags & VERIFY_WITNESS_PUBKEYTYPE
    verify_strict = not not (flags & VERIFY_STRICTENC)
    any_nonblank = (flags & VERIFY_NULLFAIL) and any(len(s) > 0 for s in sig_blobs)

    while len(sig_blobs_remaining) > 0:
        sig_blob = sig_blobs_remaining.pop()
        try:
            sig_pair, signature_type = parse_and_check_signature_blob(sig_blob, flags, vm)
        except (der.UnexpectedDER, ValueError):
            public_pair_blobs = []
        while len(sig_blobs_remaining) < len(public_pair_blobs):
            pair_blob = public_pair_blobs.pop()
            if checksig(vm, sig_pair, signature_type, pair_blob, sig_blobs,
                        sighash_cache, verify_witness_pubkeytype, verify_strict):
                break
        else:
            if any_nonblank:
                raise ScriptError("bad signature not NULL", errno.NULLFAIL)
            vm.append(vm.VM_FALSE)
            return
    vm.append(vm.VM_TRUE)


def do_OP_CHECKSIG(vm):
    pair_blob = vm.pop()
    sig_blob = vm.pop()
    checksigs(vm, [sig_blob], [pair_blob])


def do_OP_CHECKMULTISIG(vm):
    key_count = vm.pop_int()
    if key_count < 0 or key_count > 20:
        raise ScriptError("key_count not in range 0 to 20", errno.PUBKEY_COUNT)
    public_pair_blobs = [vm.pop() for _ in range(key_count)]
    public_pair_blobs.reverse()

    signature_count = vm.pop_int()
    if signature_count < 0 or signature_count > key_count:
        raise ScriptError(
            "invalid number of signatures: %d for %d keys" % (signature_count, key_count), errno.SIG_COUNT)
    sig_blobs = [vm.pop() for _ in range(signature_count)]
    sig_blobs.reverse()

    # check that we have the required hack 00 byte
    hack_byte = vm.pop()
    if vm.flags & VERIFY_NULLDUMMY and hack_byte != b'':
        raise ScriptError("bad dummy byte in checkmultisig", errno.SIG_NULLDUMMY)

    checksigs(vm, sig_blobs, public_pair_blobs)

    vm.op_count += key_count


def do_OP_CHECKMULTISIGVERIFY(vm):
    do_OP_CHECKMULTISIG(vm)
    v = vm.bool_from_script_bytes(vm.pop())
    if not v:
        raise ScriptError("VERIFY failed", errno.VERIFY)


def do_OP_CHECKSIGVERIFY(vm):
    do_OP_CHECKSIG(vm)
    v = vm.bool_from_script_bytes(vm.pop())
    if not v:
        raise ScriptError("VERIFY failed", errno.VERIFY)


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
