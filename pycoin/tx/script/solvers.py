# -*- coding: utf-8 -*-
"""
Solvers figure out what input script signs a given output script.


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
from ...encoding import public_pair_to_sec, is_sec_compressed, sec_to_public_pair,\
    hash160_sec_to_bitcoin_address, public_pair_to_bitcoin_address,\
    public_pair_to_hash160_sec

from . import der
from . import opcodes
from . import tools

bytes_from_int = chr if bytes == str else lambda x: bytes([x])

TEMPLATES = [
    tools.compile("OP_PUBKEY OP_CHECKSIG"),
    tools.compile("OP_DUP OP_HASH160 OP_PUBKEYHASH OP_EQUALVERIFY OP_CHECKSIG"),
]

class SolvingError(Exception): pass

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
    raise SolvingError("don't recognize output script")

def bitcoin_address_for_script(script):
    try:
        r = match_script_to_templates(script)
        if len(r) != 1 or len(r[0]) != 2:
            return None
        if r[0][0] == opcodes.OP_PUBKEYHASH:
            return hash160_sec_to_bitcoin_address(r[0][1])
        if r[0][0] == opcodes.OP_PUBKEY:
            sec = r[0][1]
            return public_pair_to_bitcoin_address(
                sec_to_public_pair(sec),
                compressed=is_sec_compressed(sec))
    except SolvingError:
        pass
    return None

class SecretExponentSolver(object):
    """This is an sample solver that, with a list of secret exponents, can be used
    as a solver to be passed to the "sign" method of an UnsignedTx.
    """
    def __init__(self, secret_exponent_iterator):
        self.secret_exponent_iterator = iter(secret_exponent_iterator)
        self.secret_exponent_for_public_pair_lookup = {}
        self.public_pair_compressed_for_hash160_lookup = {}

    def add_secret_exponent(self, secret_exponent):
        public_pair = ecdsa.public_pair_for_secret_exponent(ecdsa.generator_secp256k1, secret_exponent)
        self.secret_exponent_for_public_pair_lookup[public_pair] = secret_exponent
        for compressed in (True, False):
            hash160 = public_pair_to_hash160_sec(public_pair, compressed=compressed)
            self.public_pair_compressed_for_hash160_lookup[hash160] = (public_pair, compressed)

    def add_secret_exponents(self, secret_exponents):
        """Increase the space of known secret keys."""
        for secret_exponent in secret_exponents:
            self.add_secret_exponent(secret_exponent)

    def next_secret_exponent(self):
        self.add_secret_exponent(next(self.secret_exponent_iterator))

    def secret_exponent_for_public_pair(self, public_pair, compressed):
        while not public_pair in self.secret_exponent_for_public_pair_lookup:
            try:
                self.next_secret_exponent()
            except StopIteration:
                bitcoin_address = public_pair_to_bitcoin_address(public_pair, compressed=compressed)
                raise SolvingError("can't determine private key for %s" % bitcoin_address)
        return self.secret_exponent_for_public_pair_lookup[public_pair]

    def public_pair_for_hash160(self, hash160):
        while not hash160 in self.public_pair_compressed_for_hash160_lookup:
            try:
                self.next_secret_exponent()
            except StopIteration:
                bitcoin_address = hash160_sec_to_bitcoin_address(hash160)
                raise SolvingError("can't determine private key for %s" % bitcoin_address)
        return self.public_pair_compressed_for_hash160_lookup.get(hash160)

    def __call__(self, tx_out_script, signature_hash, signature_type):
        """Figure out how to create a signature for the incoming transaction, and sign it.

        tx_out_script: the tx_out script that needs to be "solved"
        signature_hash: the bignum hash value of the new transaction reassigning the coins
        signature_type: always SIGHASH_ALL (1)
        """

        if signature_hash == 0:
            raise SolvingError("signature_hash can't be 0")

        opcode_value_list = match_script_to_templates(tx_out_script)

        ba = bytearray()

        compressed = True
        for opcode, v in opcode_value_list:
            if opcode == opcodes.OP_PUBKEY:
                public_pair = sec_to_public_pair(v)
            elif opcode == opcodes.OP_PUBKEYHASH:
                public_pair, compressed = self.public_pair_for_hash160(v)
            else:
                raise SolvingError("can't determine how to sign this script")
            secret_exponent = self.secret_exponent_for_public_pair(public_pair, compressed=compressed)
            r,s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, signature_hash)
            sig = der.sigencode_der(r, s) + bytes_from_int(signature_type)
            ba += tools.compile(binascii.hexlify(sig).decode("utf8"))
            if opcode == opcodes.OP_PUBKEYHASH:
                ba += tools.compile(binascii.hexlify(public_pair_to_sec(public_pair, compressed=compressed)).decode("utf8"))

        return bytes(ba)
