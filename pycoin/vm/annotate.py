import collections
import itertools

from pycoin.encoding.hash import hash160
from pycoin.encoding.hexbytes import b2h
from pycoin.encoding.sec import is_sec_compressed, public_pair_to_hash160_sec
from pycoin.intbytes import byte2int
from pycoin.satoshi.flags import SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, SIGHASH_FORKID
from pycoin.satoshi.checksigops import parse_signature_blob
from pycoin.coins.SolutionChecker import ScriptError


class Annotate(object):
    BIT_LIST = [(SIGHASH_ANYONECANPAY, "SIGHASH_ANYONECANPAY"), (SIGHASH_FORKID, "SIGHASH_FORKID")]
    BASE_LOOKUP = {SIGHASH_ALL: "SIGHASH_ALL", SIGHASH_SINGLE: "SIGHASH_SINGLE", SIGHASH_NONE: "SIGHASH_NONE"}

    def __init__(self, script_tools, address_api):
        self._script_tools = script_tools
        self._address = address_api
        for _ in "EQUAL HASH160 CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY".split():
            setattr(self, "OP_%s" % _, byte2int(self._script_tools.compile('OP_%s' % _)))

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
        b2h_data = b2h(data)
        if len(data) == 1:
            return "OP_%d" % byte2int(data)
        return "[PUSH_%s] %s" % (opcode, b2h_data)

    def annotate_pubkey(self, blob, da):
        is_compressed = is_sec_compressed(blob)
        address = self._address.for_p2pkh(hash160(blob))
        da[blob].append("SEC for %scompressed %s" % ("" if is_compressed else "un", address))

    def annotate_signature(self, blob, da, vmc):
        lst = da[blob]
        try:
            sig_pair, sig_type = parse_signature_blob(blob)
        except ValueError:
            return
        lst.append("r: {0:#066x}".format(sig_pair[0]))
        lst.append("s: {0:#066x}".format(sig_pair[1]))
        sig_hash = vmc.signature_for_hash_type_f(sig_type, [blob], vmc)
        lst.append("z: {0:#066x}".format(sig_hash))
        lst.append("signature type %s" % self.sighash_type_to_string(sig_type))
        addresses = []
        generator = vmc.generator_for_signature_type(sig_type)
        pairs = generator.possible_public_pairs_for_signature(sig_hash, sig_pair)
        for pair in pairs:
            for comp in (True, False):
                hash160 = public_pair_to_hash160_sec(pair, compressed=comp)
                address = self._address.for_p2pkh(hash160)
                addresses.append(address)
        lst.append(" sig for %s" % " ".join(addresses))

    def annotate_checksig(self, vmc, da):
        s = list(vmc.stack)
        try:
            self.annotate_pubkey(vmc.pop(), da)
            self.annotate_signature(vmc.pop(), da, vmc)
        except (IndexError, ValueError):
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

        # the script may have ended early, so let's just double-check
        try:
            for idx, (opcode, data, pc, new_pc) in enumerate(itertools.chain(
                self._script_tools.get_opcodes(tx.unspents[tx_in_idx].script),
                    self._script_tools.get_opcodes(tx.txs_in[tx_in_idx].script))):
                if idx >= len(r):
                    r.append(([], pc, opcode, self.instruction_for_opcode(opcode, data), []))
        except IndexError:
            pass

        return r

    def annotate_spendable(self, tx_class, spendable):
        txs_in = [tx_class.TxIn(b'1' * 32, 0)]
        fake_spend_tx = tx_class(1, txs_in, [])
        fake_spend_tx.set_unspents([spendable])
        return self.annotate_scripts(fake_spend_tx, 0)
