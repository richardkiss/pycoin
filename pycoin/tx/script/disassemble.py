import collections

from pycoin.encoding import (
    hash160, hash160_sec_to_bitcoin_address, public_pair_to_bitcoin_address, sec_to_public_pair, is_sec_compressed
)

from pycoin.serialize import b2h
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools  # BRAIN DAMAGE

from pycoin.tx.script import ScriptError
from pycoin.tx.script.checksigops import parse_signature_blob
from pycoin.tx.script.flags import SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, SIGHASH_FORKID


for _ in "EQUAL HASH160 CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY".split():
    exec("OP_%s = BitcoinScriptTools.int_for_opcode('OP_%s')" % (_, _))


ADDRESS_PREFIX = b'\0'  # BRAIN DAMAGE


def sighash_type_to_string(sighash_type):
    anyonecanpay = sighash_type & SIGHASH_ANYONECANPAY
    forkid = sighash_type & SIGHASH_FORKID
    sighash_type &= ~SIGHASH_ANYONECANPAY & ~SIGHASH_FORKID
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
    if forkid:
        sighash_str += ' | SIGHASH_FORKID'
    return sighash_str


def instruction_for_opcode(opcode, data):
    if data is None or len(data) == 0:
        return BitcoinScriptTools.disassemble_for_opcode_data(opcode, data)
    return "[PUSH_%d] %s" % (opcode, b2h(data))


def annotate_pubkey(blob, da):
    l = da[blob]
    is_compressed = is_sec_compressed(blob)
    address = hash160_sec_to_bitcoin_address(hash160(blob))
    l.append("SEC for %scompressed %s" % ("" if is_compressed else "un", address))


def annotate_signature(blob, da, vmc):
    l = da[blob]
    sig_pair, sig_type = parse_signature_blob(blob)
    l.append("r: {0:#066x}".format(sig_pair[0]))
    l.append("s: {0:#066x}".format(sig_pair[1]))
    sig_hash = vmc.signature_for_hash_type_f(sig_type, [blob], vmc)
    l.append("z: {0:#066x}".format(sig_hash))
    l.append("signature type %s" % sighash_type_to_string(sig_type))
    addresses = []
    generator = vmc.generator_for_signature_type(sig_type)
    pairs = generator.possible_public_pairs_for_signature(sig_hash, sig_pair)
    for pair in pairs:
        for comp in (True, False):
            address = public_pair_to_bitcoin_address(pair, compressed=comp, address_prefix=ADDRESS_PREFIX)
            addresses.append(address)
    l.append(" sig for %s" % " ".join(addresses))


def annotate_checksig(vmc, da):
    s = list(vmc.stack)
    try:
        annotate_pubkey(vmc.pop(), da)
        annotate_signature(vmc.pop(), da, vmc)
    except IndexError:
        pass
    vmc.stack = s


def annotate_checkmultisig(vmc, da):
    s = list(vmc.stack)
    try:
        key_count = vmc.pop_int()
        while key_count > 0:
            key_count -= 1
            annotate_pubkey(vmc.pop(), da)

        signature_count = vmc.pop_int()
        while signature_count > 0:
            signature_count -= 1
            annotate_signature(vmc.pop(), da, vmc)
    except IndexError:
        pass
    vmc.stack = s


def annotate_scripts(tx, tx_in_idx):
    "return list of pre_annotations, pc, opcode, instruction, post_annotations"
    # input_annotations_f, output_annotations_f = annotation_f_for_scripts(tx, tx_in_idx)

    data_annotations = collections.defaultdict(list)

    def traceback_f(opcode, data, pc, vmc):
        if opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            annotate_checksig(vmc, data_annotations)
        if opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
            annotate_checkmultisig(vmc, data_annotations)
        return

    try:
        tx.check_solution(tx_in_idx, traceback_f=traceback_f)
    except ScriptError:
        pass

    r = []

    def traceback_f(opcode, data, pc, vmc):
        a0 = []
        if vmc.pc == 0:
            if vmc.is_solution_script:
                a0.append("--- SIGNATURE SCRIPT START")
            else:
                a0.append("--- PUBLIC KEY SCRIPT START")
        r.append((a0, vmc.pc, opcode, instruction_for_opcode(opcode, data), data_annotations[data]))

    try:
        tx.check_solution(tx_in_idx, traceback_f=traceback_f)
    except ScriptError:
        pass

    return r


def annotate_spendable(tx_class, spendable):
    txs_in = [tx_class.TxIn(b'1' * 32, 0)]
    fake_spend_tx = tx_class(1, txs_in, [])
    fake_spend_tx.set_unspents([spendable])
    return annotate_scripts(fake_spend_tx, 0)
