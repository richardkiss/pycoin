from pycoin.ecdsa import generator_secp256k1, possible_public_pairs_for_signature
from pycoin.encoding import (public_pair_to_bitcoin_address, hash160_sec_to_bitcoin_address,
                             sec_to_public_pair, is_sec_compressed)

from pycoin.serialize import b2h
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.SolutionChecker import BitcoinSolutionChecker, check_solution

from pycoin.tx.script import ScriptError
from pycoin.tx.script.checksigops import parse_signature_blob
from pycoin.tx.script.flags import SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY
from pycoin.tx.Tx import Tx
from pycoin.tx.TxIn import TxIn


def sighash_type_to_string(sighash_type):
    anyonecanpay = sighash_type & SIGHASH_ANYONECANPAY
    sighash_type &= ~SIGHASH_ANYONECANPAY
    if sighash_type == SIGHASH_ALL:
        sighash_str = 'SIGHASH_ALL'
    elif sighash_type == SIGHASH_NONE:
        sighash_str = 'SIGHASH_NONE'
    elif sighash_type == SIGHASH_SINGLE:
        sighash_str = 'SIGHASH_SINGLE'
    else:
        sighash_str = 'SIGHASH_UNKNOWN'
    if anyonecanpay:
        sighash_str += ' | SIGHASH_ANYONECANPAY'
    return sighash_str


def add_signature_annotations(annotations, signature_blob, vmc):
    sig_pair, sig_type = parse_signature_blob(signature_blob)
    annotations.append("r: {0:#066x}".format(sig_pair[0]))
    annotations.append("s: {0:#066x}".format(sig_pair[1]))
    sig_hash = vmc.signature_for_hash_type_f(sig_type, [signature_blob], vmc)
    annotations.append("z: {0:#066x}".format(sig_hash))
    annotations.append("signature type %s" % sighash_type_to_string(sig_type))
    addresses = []
    pairs = possible_public_pairs_for_signature(generator_secp256k1, sig_hash, sig_pair)
    for pair in pairs:
        for comp in (True, False):
            address = public_pair_to_bitcoin_address(pair, compressed=comp, address_prefix=b'\0')
            addresses.append(address)
    annotations.append(" sig for %s" % " ".join(addresses))


def add_address_annotations(annotations, hash160_blob, address_prefix):
    address = hash160_sec_to_bitcoin_address(hash160_blob, address_prefix=address_prefix)
    annotations.append("%s... corresponds to %s" % (b2h(hash160_blob)[:12], address))


def add_sec_annotations(a1, data, address_prefix):
    pair = sec_to_public_pair(data)
    is_compressed = is_sec_compressed(data)
    a1.append("SEC for %scompressed %s" % (
            "" if is_compressed else "un", public_pair_to_bitcoin_address(
                pair, compressed=is_compressed, address_prefix=address_prefix)))


def instruction_for_opcode(opcode, data):
    if data is None or len(data) == 0:
        return BitcoinScriptTools.disassemble_for_opcode_data(opcode, data)
    return "[PUSH_%d] %s" % (opcode, b2h(data))


def _make_input_annotations_f(tx, tx_in_idx):
    is_p2sh = BitcoinSolutionChecker.is_pay_to_script_hash(tx.unspents[tx_in_idx].script)
    in_ap = b'\0'

    def input_annotations_f(new_pc, opcode, data, vmc):
        a0, a1 = [], []
        if vmc.pc == 0:
            a0.append("--- SIGNATURE SCRIPT START")
        ld = len(data) if data is not None else 0
        if ld in (71, 72) and not is_p2sh:
            add_signature_annotations(a1, data, vmc)
        if ld == 20:
            add_address_annotations(a1, data, address_prefix=in_ap)
        if ld in (33, 65):
            add_sec_annotations(a1, data, address_prefix=in_ap)
        return a0, a1
    return input_annotations_f


def _make_output_annotations_f(tx, tx_in_idx):
    is_p2sh = BitcoinSolutionChecker.is_pay_to_script_hash(tx.unspents[tx_in_idx].script)
    out_ap = b'\0'
    if is_p2sh:
        out_ap = b'\5'

    def output_annotations_f(new_pc, opcode, data, vmc):
        a0, a1 = [], []
        if vmc.pc == 0:
            a0.append("--- PUBLIC KEY SCRIPT START")
        ld = len(data) if data is not None else 0
        if ld == 20:
            add_address_annotations(a1, data, address_prefix=out_ap)
        if ld in (33, 65):
            add_sec_annotations(a1, data, address_prefix=out_ap)
        return a0, a1
    return output_annotations_f


def annotation_f_for_scripts(tx, tx_in_idx):
    iaf = _make_input_annotations_f(tx, tx_in_idx)
    oaf = _make_output_annotations_f(tx, tx_in_idx)

    return iaf, oaf


def annotate_scripts(tx, tx_in_idx):
    "return list of pre_annotations, pc, opcode, instruction, post_annotations"
    r = []
    input_annotations_f, output_annotations_f = annotation_f_for_scripts(tx, tx_in_idx)

    def traceback_f(opcode, data, pc, vmc):
        if vmc.is_solution_script:
            pre_annotations, post_annotations = input_annotations_f(pc, opcode, data, vmc)
        else:
            pre_annotations, post_annotations = output_annotations_f(pc, opcode, data, vmc)
        r.append((pre_annotations, vmc.pc, opcode, instruction_for_opcode(opcode, data), post_annotations))
        return

    try:
        check_solution(tx, tx_in_idx, traceback_f=traceback_f)
    except ScriptError:
        pass
    return r


def annotate_spendable(spendable):
    txs_in = [TxIn(b'\0' * 32, 0)]
    fake_spend_tx = Tx(1, txs_in, [])
    fake_spend_tx.set_unspents([spendable])
    return annotate_scripts(fake_spend_tx, 0)
