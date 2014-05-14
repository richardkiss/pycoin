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
from ... import networks
from ...encoding import public_pair_to_sec, hash160, is_sec_compressed, sec_to_public_pair,\
    hash160_sec_to_bitcoin_address, public_pair_to_bitcoin_address,\
    public_pair_to_hash160_sec

from . import der
from . import opcodes
from . import tools

bytes_from_int = chr if bytes == str else lambda x: bytes([x])


TEMPLATES = [
    ("coinbase", tools.compile("OP_PUBKEY OP_CHECKSIG")),
    ("standard", tools.compile("OP_DUP OP_HASH160 OP_PUBKEYHASH OP_EQUALVERIFY OP_CHECKSIG")),
    ("pay_to_script", tools.compile("OP_HASH160 OP_PUBKEYHASH OP_EQUAL"))
]


class SolvingError(Exception):
    pass


def match_script_to_templates(script):
    """
    Examine the script passed in by tx_out_script and see if it
    matches the form of one of the templates in TEMPLATES. If so,
    return the form it matches; otherwise, return None.
    """

    for name, template in TEMPLATES:
        r = []
        pc1 = pc2 = 0
        while 1:
            if pc1 == len(script) and pc2 == len(template):
                return name, r
            if pc1 >= len(script) or pc2 >= len(template):
                break
            opcode1, data1, pc1 = tools.get_opcode(script, pc1)
            opcode2, data2, pc2 = tools.get_opcode(template, pc2)
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


def script_type_and_hash160(script):
    name, r = match_script_to_templates(script)
    if r[0][0] == opcodes.OP_PUBKEYHASH:
        return name, r[0][1]
    if r[0][0] == opcodes.OP_PUBKEY:
        return name, hash160(r[0][1])
    raise SolvingError("don't recognize output script")


def payable_address_for_script(script, netcode="BTC"):
    """
    Return the payment type and the hash160 for a given script.
    The payment type is one of "coinbase", "standard", "pay_to_script".
    """
    try:
        name, the_hash160 = script_type_and_hash160(script)
    except SolvingError:
        return None

    if name == "pay_to_script":
        address_prefix = networks.pay_to_script_prefix_for_netcode(netcode)
    else:
        address_prefix = networks.address_prefix_for_netcode(netcode)
    return hash160_sec_to_bitcoin_address(the_hash160, address_prefix=address_prefix)


def canonical_solver(tx_out_script, signature_hash, signature_type, hash160_lookup):
    """
    Figure out how to create a signature for the incoming transaction, and sign it.

    tx_out_script: the tx_out script that needs to be "solved"
    signature_hash: the bignum hash value of the new transaction reassigning the coins
    signature_type: always SIGHASH_ALL (1)
    """

    if signature_hash == 0:
        raise SolvingError("signature_hash can't be 0")

    name, opcode_value_list = match_script_to_templates(tx_out_script)

    ba = bytearray()

    order = ecdsa.generator_secp256k1.order()

    compressed = True
    for opcode, v in opcode_value_list:
        if opcode == opcodes.OP_PUBKEY:
            v = hash160(v)
        elif opcode != opcodes.OP_PUBKEYHASH:
            raise SolvingError("can't determine how to sign this script")
        result = hash160_lookup.get(v)
        if result is None:
            bitcoin_address = hash160_sec_to_bitcoin_address(v)
            raise SolvingError("can't determine private key for %s" % bitcoin_address)
        secret_exponent, public_pair, compressed = result
        r,s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, signature_hash)
        if s + s > order:
            s = order - s
        sig = der.sigencode_der(r, s) + bytes_from_int(signature_type)
        ba += tools.compile(binascii.hexlify(sig).decode("utf8"))
        if opcode == opcodes.OP_PUBKEYHASH:
            ba += tools.compile(binascii.hexlify(public_pair_to_sec(public_pair, compressed=compressed)).decode("utf8"))

    return bytes(ba)


def build_hash160_lookup_db(secret_exponents):
    d = {}
    for secret_exponent in secret_exponents:
        public_pair = ecdsa.public_pair_for_secret_exponent(ecdsa.generator_secp256k1, secret_exponent)
        for compressed in (True, False):
            hash160 = public_pair_to_hash160_sec(public_pair, compressed=compressed)
            d[hash160] = (secret_exponent, public_pair, compressed)
    return d
