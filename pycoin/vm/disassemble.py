import collections

from pycoin.encoding import (
    hash160, hash160_sec_to_bitcoin_address, public_pair_to_bitcoin_address, is_sec_compressed
)

from pycoin.serialize import b2h

from pycoin.satoshi.flags import SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, SIGHASH_FORKID
from pycoin.satoshi.checksigops import parse_signature_blob
from pycoin.coins.SolutionChecker import ScriptError



ADDRESS_PREFIX = b'\0'  # BRAIN DAMAGE


class Disassemble(object):
    BIT_LIST = [(SIGHASH_ANYONECANPAY, "SIGHASH_ANYONECANPAY"), (SIGHASH_FORKID, "SIGHASH_FORKID")]
    BASE_LOOKUP = { SIGHASH_ALL: "SIGHASH_ALL", SIGHASH_SINGLE: "SIGHASH_SINGLE", SIGHASH_NONE: "SIGHASH_NONE" }

    def __init__(self, script_tools):
        self._script_tools = script_tools
        for _ in "EQUAL HASH160 CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY".split():
            setattr(self, "OP_%s" % _, self._script_tools.int_for_opcode('OP_%s' % _))

    def sighash_type_to_string(self, sighash_type):
        v = sighash_type
        flag_bit_list = []
        for flag_bit, flag_name in self.BIT_LIST:
            if v & flag_bit:
                v &= ~flag_bit
                flag_bit_list.append(flag_name)
        base_type = self.BASE_LOOKUP.get(v, "SIGHASH_UNKNOWN")
        return "".join([base_type] + [" | %s" % s for s in flag_bit_list])

    def instruction_for_opcode(self, opcode, data):
        if data is None or len(data) == 0:
            return self._script_tools.disassemble_for_opcode_data(opcode, data)
        return "[PUSH_%d] %s" % (opcode, b2h(data))

    def annotate_pubkey(self, blob, da):
        l = da[blob]
        is_compressed = is_sec_compressed(blob)
        address = hash160_sec_to_bitcoin_address(hash160(blob))
        l.append("SEC for %scompressed %s" % ("" if is_compressed else "un", address))

    def annotate_signature(self, blob, da, vmc):
        l = da[blob]
        sig_pair, sig_type = parse_signature_blob(blob)
        l.append("r: {0:#066x}".format(sig_pair[0]))
        l.append("s: {0:#066x}".format(sig_pair[1]))
        sig_hash = vmc.signature_for_hash_type_f(sig_type, [blob], vmc)
        l.append("z: {0:#066x}".format(sig_hash))
        l.append("signature type %s" % self.sighash_type_to_string(sig_type))
        addresses = []
        generator = vmc.generator_for_signature_type(sig_type)
        pairs = generator.possible_public_pairs_for_signature(sig_hash, sig_pair)
        for pair in pairs:
            for comp in (True, False):
                address = public_pair_to_bitcoin_address(pair, compressed=comp, address_prefix=ADDRESS_PREFIX)
                addresses.append(address)
        l.append(" sig for %s" % " ".join(addresses))

    def annotate_checksig(self, vmc, da):
        s = list(vmc.stack)
        try:
            self.annotate_pubkey(vmc.pop(), da)
            self.annotate_signature(vmc.pop(), da, vmc)
        except IndexError:
            pass
        vmc.stack = s

    def annotate_checkmultisig(self, vmc, da):
        s = list(vmc.stack)
        try:
            key_count = vmc.pop_int()
            while key_count > 0:
                key_count -= 1
                self.annotate_pubkey(vmc.pop(), da)

            signature_count = vmc.pop_int()
            while signature_count > 0:
                signature_count -= 1
                self.annotate_signature(vmc.pop(), da, vmc)
        except IndexError:
            pass
        vmc.stack = s

    def annotate_scripts(self, tx, tx_in_idx):
        "return list of pre_annotations, pc, opcode, instruction, post_annotations"
        # input_annotations_f, output_annotations_f = annotation_f_for_scripts(tx, tx_in_idx)

        data_annotations = collections.defaultdict(list)

        def traceback_f(opcode, data, pc, vmc):
            if opcode in (self.OP_CHECKSIG, self.OP_CHECKSIGVERIFY):
                self.annotate_checksig(vmc, data_annotations)
            if opcode in (self.OP_CHECKMULTISIG, self.OP_CHECKMULTISIGVERIFY):
                self.annotate_checkmultisig(vmc, data_annotations)
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
            r.append((a0, vmc.pc, opcode, self.instruction_for_opcode(opcode, data), data_annotations[data]))

        try:
            tx.check_solution(tx_in_idx, traceback_f=traceback_f)
        except ScriptError:
            pass

        return r

    def annotate_spendable(self, tx_class, spendable):
        txs_in = [tx_class.TxIn(b'1' * 32, 0)]
        fake_spend_tx = tx_class(1, txs_in, [])
        fake_spend_tx.set_unspents([spendable])
        return self.annotate_scripts(fake_spend_tx, 0)
