# -*- coding: utf-8 -*-
"""
Sign and verify Bitcoin transactions.

These functions were adapted from the Bitcoin-QT client, as of around 0.31,
for maximum compatibility. Some of what's going on is a bit cryptic.


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

import binascii

from ... import ecdsa
from ...encoding import public_pair_to_sec, public_pair_from_sec,\
    hash160_sec_to_bitcoin_address, public_pair_to_bitcoin_address

from . import der
from . import opcodes
from . import tools

from . import ScriptError

from .microcode import VCH_TRUE

bytes_from_int = chr if bytes == str else lambda x: bytes([x])

TEMPLATES = [
    tools.compile("OP_PUBKEY OP_CHECKSIG"),
    tools.compile("OP_DUP OP_HASH160 OP_PUBKEYHASH OP_EQUALVERIFY OP_CHECKSIG"),
]

class SigningError(Exception): pass

def match_script_to_templates(script1):
    """Examine the script passed in by tx_out_script and see if it
    matches the form of one of the templates in TEMPLATES. If so,
    return the form it matches; otherwise, return None."""
    for script2 in TEMPLATES:
        r = []
        pc1 = pc2 = 0
        while 1:
            if pc1 == len(script1) and pc2 == len(script2):
                return r
            opcode1, data1, pc1 = tools.get_opcode(script1, pc1)
            opcode2, data2, pc2 = tools.get_opcode(script2, pc2)
            if opcode2 == opcodes.OP_PUBKEY:
                l1 = len(data1)
                if l1 < 33 or l1 > 120:
                    break
                r.append((opcode2, data1))
            elif opcode2 == opcodes.OP_PUBKEYHASH:
                if len(data1) != 160/8:
                    break
                r.append((opcode2, data1))
            elif (opcode1, data1) != (opcode2, data2):
                break
    return None

def solver(tx_out_script, partial_hash, secret_exponent_key_for_public_pair_lookup, public_pair_compressed_for_hash160_sec, signature_type):
    """Figure out how to create a signature for the incoming transaction, and sign it.

    tx_out_script: the tx_out script that needs to be "solved"
    partial_hash: the bignum hash value of the new transaction reassigning the coins
    secret_exponent_key_for_public_pair_lookup: a function that returns the
        secret_exponent for the given public_pair
    public_pair_compressed_for_hash160_sec: a function returns a tuple
        (public_pair, compressed) for a given hash160_sec
    signature_type: always SIGHASH_ALL (1)
    """

    if partial_hash == 0:
        raise SigningError("partial_hash can't be 0")

    opcode_value_list = match_script_to_templates(tx_out_script)
    if not opcode_value_list:
        raise SigningError("don't recognize output script")

    ba = bytearray()

    compressed = True
    for opcode, v in opcode_value_list:
        if opcode == opcodes.OP_PUBKEY:
            public_pair = public_pair_from_sec(v)
        elif opcode == opcodes.OP_PUBKEYHASH:
            the_tuple = public_pair_compressed_for_hash160_sec(v)
            if the_tuple is None:
                bitcoin_address = hash160_sec_to_bitcoin_address(v)
                raise SigningError("can't determine private key for %s" % bitcoin_address)
            public_pair, compressed = the_tuple
        else:
            raise SigningError("can't determine how to sign this script")
        secret_exponent = secret_exponent_key_for_public_pair_lookup(public_pair)
        if secret_exponent is None:
            bitcoin_address = public_pair_to_bitcoin_address(public_pair, compressed=compressed)
            raise SigningError("can't determine private key for %s" % bitcoin_address)
        r,s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, partial_hash)
        sig = der.sigencode_der(r, s) + bytes_from_int(signature_type)
        ba += tools.compile(binascii.hexlify(sig).decode("utf8"))
        if opcode == opcodes.OP_PUBKEYHASH:
            ba += tools.compile(binascii.hexlify(public_pair_to_sec(public_pair, compressed=compressed)))

    return bytes(ba)

def verify_script_signature(script, tx_hash, public_key_blob, sig_blob, hash_type):
    """Ensure the given transaction has the correct signature. Invoked by the VM.
    Adapted from official Bitcoin-QT client.

    script: the script that is claimed to unlock the coins used in this transaction
    tx_hash: the partial hash of the transaction being verified
    public_key_blob: the blob representing the SEC-encoded public pair
    sig_blob: the blob representing the DER-encoded signature
    hash_type: expected signature_type (or 0 for wild card)
    """
    signature_type = ord(sig_blob[-1:])
    if signature_type != 1:
        raise ScriptError("unknown signature type %d" % signature_type)
    sig_pair = der.sigdecode_der(sig_blob[:-1])
    if hash_type == 0:
        hash_type = signature_type
    elif hash_type != signature_type:
        raise ScriptError("wrong hash type")
    public_pair = public_pair_from_sec(public_key_blob)
    v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, tx_hash, sig_pair)
    return v
