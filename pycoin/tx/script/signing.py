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
from ...encoding import from_bytes_32
from ...encoding import public_pair_to_sec, public_pair_from_sec,\
    ripemd160_sha256_sec_to_bitcoin_address, public_pair_to_bitcoin_address

from . import der
from . import opcodes
from . import tools

from . import ScriptError

from .microcode import VCH_TRUE

bytes_from_int = chr if bytes == str else lambda x: bytes([x])

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

TEMPLATES = [
    tools.compile("OP_PUBKEY OP_CHECKSIG"),
    tools.compile("OP_DUP OP_HASH160 OP_PUBKEYHASH OP_EQUALVERIFY OP_CHECKSIG"),
]

class SigningError(Exception): pass

def match_script_to_templates(script_public_key):
    """Examine the script passed in by script_public_key and see if it
    matches the form of one of the templates in TEMPLATES. If so,
    return the form it matches; otherwise, return None."""
    script1 = script_public_key
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

def signature_hash(script, the_tx, n_in, hash_type):
    """Return the canonical hash for a transaction. We need to
    remove references to the signature, since it's a signature
    of the hash before the signature is applied.

    # TODO: move this into Tx

    script:
    the_tx:
    n_in:
    hash_type:
    """

    # first off, make a copy of the the_tx
    tx_tmp = the_tx.clone()

    # In case concatenating two scripts ends up with two codeseparators,
    # or an extra one at the end, this prevents all those possible incompatibilities.
    script = tools.delete_subscript(script, [opcodes.OP_CODESEPARATOR])

    # blank out other inputs' signatures
    for i in range(len(tx_tmp.txs_in)):
        tx_tmp.txs_in[i].script = b''
    tx_tmp.txs_in[n_in].script = script

    # Blank out some of the outputs
    if (hash_type & 0x1f) == SIGHASH_NONE:
        # Wildcard payee
        tx_tmp.txs_out = []

        # Let the others update at will
        for i in range(len(tx_tmp.txs_in)):
            if i != n_in:
                tx_tmp.txs_in[i].sequence = 0

    elif (hash_type & 0x1f) == SIGHASH_SINGLE:
        # Only lockin the txout payee at same index as txin
        n_out = n_in
        for i in range(n_out):
            tx_tmp.txs_out[i].coin_value = -1
            tx_tmp.txs_out[i].script = ''

        # Let the others update at will
        for i in range(len(tx_tmp.txs_in)):
            if i != n_in:
                tx_tmp.txs_in[i].sequence = 0

    # Blank out other inputs completely, not recommended for open transactions
    if hash_type & SIGHASH_ANYONECANPAY:
        tx_tmp.txs_in = [tx_tmp.txs_in[n_in]]

    return from_bytes_32(tx_tmp.hash(hash_type=hash_type))

def solver(script_public_key, hash, n_hash_type, secret_exponent_key_for_public_pair_lookup, public_pair_compressed_for_ripemd160_sha256_sec):
    """Figure out how to create a signature for the incoming transaction, and sign it.

    script_public_key: the tx_out script that needs to be "solved"
    hash: the bignum hash value of the new transaction reassigning the coins
    n_hash_type: always SIGHASH_ALL (1)
    secret_exponent_key_for_public_pair_lookup: a function that returns the
        secret_exponent for the given public_pair
    public_pair_compressed_for_ripemd160_sha256_sec: a function returns a tuple
        (public_pair, compressed) for a given ripemd160_sha256_sec
    """
    # n_hash_type => 1

    opcode_value_list = match_script_to_templates(script_public_key)
    if not opcode_value_list:
        return None

    if hash == 0:
        raise SigningError("hash can't be 0")

    ba = bytearray()

    compressed = True
    for opcode, v in opcode_value_list:
        if opcode not in (opcodes.OP_PUBKEY, opcodes.OP_PUBKEYHASH):
            return None
        if opcode == opcodes.OP_PUBKEY:
            public_pair = public_pair_from_sec(v)
        else:
            the_tuple = public_pair_compressed_for_ripemd160_sha256_sec(v)
            if the_tuple is None:
                bitcoin_address = ripemd160_sha256_sec_to_bitcoin_address(v)
                raise SigningError("can't determine public key for %s" % bitcoin_address)
            public_pair, compressed = the_tuple
        secret_exponent = secret_exponent_key_for_public_pair_lookup(public_pair)
        if secret_exponent is None:
            bitcoin_address = public_pair_to_bitcoin_address(public_pair, compressed=compressed)
            raise SigningError("can't determine private key for %s" % bitcoin_address)
        r,s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, hash)
        sig = der.sigencode_der(r, s) + bytes_from_int(n_hash_type)
        ba += tools.compile(binascii.hexlify(sig).decode("utf8"))
        if opcode == opcodes.OP_PUBKEYHASH:
            ba += tools.compile(binascii.hexlify(public_pair_to_sec(public_pair, compressed=compressed)))

    return bytes(ba)

def sign_signature(tx_from, tx_to, n_in, secret_exponent_key_for_public_pair_lookup, public_key_for_hash, hash_type=SIGHASH_ALL, script_prereq=b''):
    # tx_from : the Tx where that has a TxOut assigned to this public key
    # tx_to : the Tx that's being newly formed. All but the script is set.
    # n_in: index
    tx_in = tx_to.txs_in[n_in]
    tx_out = tx_from.txs_out[tx_in.previous_index]
    assert tx_from.hash() == tx_in.previous_hash

    # Leave out the signature from the hash, since a signature can't sign itself.
    # The checksig op will also drop the signatures from its hash.
    the_hash = signature_hash(script_prereq + tx_out.script, tx_to, n_in, hash_type)

    new_script = solver(tx_out.script, the_hash, hash_type, secret_exponent_key_for_public_pair_lookup, public_key_for_hash)
    if not new_script:
        return False
    return script_prereq + new_script + tx_in.script

def verify_script_signature(script, tx_to, n_in, public_key_blob, sig_blob, subscript, hash_type):
    signature_type = ord(sig_blob[-1:])
    if signature_type != 1:
        raise ScriptError("unknown signature type %d" % signature_type)
    sig_pair = der.sigdecode_der(sig_blob[:-1])
    # drop the signature, since there's no way for a signature to sign itself
    subscript = tools.delete_subscript(subscript, tools.compile(binascii.hexlify(sig_blob).decode("utf8")))
    if hash_type == 0:
        hash_type = signature_type
    elif hash_type != signature_type:
        raise ScriptError("wrong hash type")
    the_hash = signature_hash(script, tx_to, n_in, hash_type)
    public_pair = public_pair_from_sec(public_key_blob)
    v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, the_hash, sig_pair)
    return v
