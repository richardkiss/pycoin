
import binascii
import logging
import io
import struct

from ... import ecdsa
from ...encoding import public_pair_to_sec, public_pair_from_sec, double_sha256

from . import der
from . import opcodes
from . import tools

from .microcode import VCH_TRUE

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

TEMPLATES = [
    tools.compile("OP_PUBKEY OP_CHECKSIG"),
    tools.compile("OP_DUP OP_HASH160 OP_PUBKEYHASH OP_EQUALVERIFY OP_CHECKSIG"),
]

def match_script_to_templates(script_public_key):
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

def solver(script_public_key, hash, n_hash_type, secret_exponent_key_for_public_pair_lookup, public_key_for_hash):
    # n_hash_type => 1

    opcode_value_list = match_script_to_templates(script_public_key)
    if not opcode_value_list:
        return None

    ba = bytearray()

    for opcode, v in opcode_value_list:
        if opcode not in (opcodes.OP_PUBKEY, opcodes.OP_PUBKEYHASH):
            return None
        if opcode == opcodes.OP_PUBKEY:
            public_pair = public_pair_from_sec(v)
        else:
            public_pair, compressed = public_key_for_hash(v)
        if hash != 0:
            secret_exponent = secret_exponent_key_for_public_pair_lookup(public_pair)
            r,s = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, hash)
            sig = sigencode_der(r, s) + bytes([n_hash_type])
            ba += tools.compile(binascii.hexlify(sig).decode("utf8"))
            if opcode == opcodes.OP_PUBKEYHASH:
                ba += tools.compile(binascii.hexlify(public_pair_to_sec(public_pair, compressed=compressed)))

    return bytes(ba)

def signature_hash(script, tx_to, n_in, hash_type):
    if n_in >= len(tx_to.txs_in):
        raise Exception("transaction index n_in out of range")

    s = io.BytesIO()
    tx_to.stream(s)
    tx_tmp = tx_to.parse(io.BytesIO(s.getvalue()))

    # In case concatenating two scripts ends up with two codeseparators,
    # or an extra one at the end, this prevents all those possible incompatibilities.
    script = delete_subscript(script, [opcodes.OP_CODESEPARATOR])

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
        if n_out >= len(tx_tmp.txs_out):
            raise Exception("transaction index n_out out of range")

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

    s = io.BytesIO()
    tx_tmp.stream(s)
    s.write(struct.pack("<L", hash_type))
    v = double_sha256(s.getvalue())
    return int.from_bytes(v, byteorder="big")

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

def delete_subscript(script, subscript):
    new_script = bytearray()
    pc = 0
    size = len(subscript)
    while pc < len(script):
        if script[pc:pc+size] == subscript:
            pc += size
            continue
        opcode, data, pc = tools.get_opcode(script, pc)
        new_script.append(opcode)
        new_script += data
    return bytes(new_script)

def verify_script_signature(script, tx_to, n_in, public_key_blob, sig_blob, subscript, hash_type):
    if sig_blob[-1] != 1:
        raise ScriptError("unknown signature type %d" % sig_blob[-1])
    sig_pair = sigdecode_der(sig_blob[:-1])
    # drop the signature, since there's no way for a signature to sign itself
    subscript = delete_subscript(subscript, tools.compile(binascii.hexlify(sig_blob).decode("utf8")))
    if hash_type == 0:
        hash_type = sig_blob[-1]
    elif hash_type != sig_blob[-1]:
        raise ScriptError("wrong hash type")
    the_hash = signature_hash(script, tx_to, n_in, hash_type)
    public_pair = public_pair_from_sec(public_key_blob)
    v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, the_hash, sig_pair)
    return v

def sigencode_der(r, s):
    return der.encode_sequence(der.encode_integer(r), der.encode_integer(s))

def sigdecode_der(sig_der):
    rs_strings, empty = der.remove_sequence(sig_der)
    if empty != b"":
        raise der.UnexpectedDER("trailing junk after DER sig: %s" %
                                binascii.hexlify(empty))
    r, rest = der.remove_integer(rs_strings)
    s, empty = der.remove_integer(rest)
    if empty != b"":
        raise der.UnexpectedDER("trailing junk after DER numbers: %s" %
                                binascii.hexlify(empty))
    return r, s
