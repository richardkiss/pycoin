import binascii

from ..coins.bitcoin.ScriptTools import BitcoinScriptTools  # BRAIN DAMAGE
from ..coins.bitcoin.SolutionChecker import BitcoinSolutionChecker  # BRAIN DAMAGE
from ..ecdsa.secp256k1 import secp256k1_generator
from ..encoding.sec import is_sec, public_pair_to_hash160_sec, sec_to_public_pair, EncodingError

from pycoin.satoshi.checksigops import parse_signature_blob
from pycoin.satoshi.der import UnexpectedDER


class WhoSigned(object):
    def __init__(self, script_tools):
        self._script_tools = script_tools

    def public_pairs_for_script(self, script, generator):
        """
        For a given script, iterate over and pull out public pairs encoded as sec values.
        """
        public_pairs = []
        for opcode, data, pc, new_pc in self._script_tools.get_opcodes(script):
            if data:
                try:
                    public_pairs.append(sec_to_public_pair(data, generator))
                except EncodingError:
                    pass
        return public_pairs

    def secs_for_script(self, script):
        """
        For a given script, iterate over and pull out public pairs encoded as sec values.
        """
        secs = []
        for opcode, data, pc, new_pc in self._script_tools.get_opcodes(script):
            if data and is_sec(data):
                secs.append(data)
        return secs

    def extract_parent_tx_out_script(self, tx, tx_in_idx):
        if len(tx.unspents) <= tx_in_idx or tx.unspents[tx_in_idx] is None:
            return b''
        parent_tx_out_script = tx.unspents[tx_in_idx].script
        sc = tx.SolutionChecker(tx)
        if sc.is_pay_to_script_hash(parent_tx_out_script):
            tx_context = sc.tx_context_for_idx(tx_in_idx)
            stack, solution_stack = sc._check_solution(tx_context, flags=0, traceback_f=None)
            parent_tx_out_script = solution_stack[-1]
        return parent_tx_out_script

    def extract_signatures(self, tx, tx_in_idx):
        tx_in = tx.txs_in[tx_in_idx]

        parent_tx_out_idx = tx_in.previous_index
        parent_tx_out_script = self.extract_parent_tx_out_script(tx, tx_in_idx)

        script = tx_in.script
        sc = tx.SolutionChecker(tx)
        for opcode, data, pc, new_pc in self._script_tools.get_opcodes(script):
            if data is None:
                continue
            try:
                sig_pair, sig_type = parse_signature_blob(data)
                sig_hash = sc.signature_hash(parent_tx_out_script, parent_tx_out_idx, sig_type)
                yield (data, sig_hash)
            except (ValueError, TypeError, UnexpectedDER):
                continue

    def public_pairs_signed(self, tx, tx_in_idx):
        signed_by = []

        parent_tx_out_script = self.extract_parent_tx_out_script(tx, tx_in_idx)
        public_pairs = self.public_pairs_for_script(parent_tx_out_script, secp256k1_generator)

        for signature, sig_hash in self.extract_signatures(tx, tx_in_idx):
            sig_pair, sig_type = parse_signature_blob(signature)

            for public_pair in public_pairs:
                if secp256k1_generator.verify(public_pair, sig_hash, sig_pair):
                    signed_by.append((public_pair, sig_pair, sig_type))
        return signed_by

    def who_signed_tx(self, tx, tx_in_idx, ui):
        """
        Given a transaction (tx) an input index (tx_in_idx), attempt to figure
        out which addresses where used in signing (so far). This method
        depends on tx.unspents being properly configured. This should work on
        partially-signed MULTISIG transactions (it will return as many
        addresses as there are good signatures).
        Returns a list of (public_pairs, sig_type) pairs.
        """
        public_pair_sig_type_list = self.public_pairs_signed(tx, tx_in_idx)
        sig_type_list = [pp[-1] for pp in public_pair_sig_type_list]
        hash160_list = [public_pair_to_hash160_sec(pp[0]) for pp in public_pair_sig_type_list]
        address_list = [ui.address_for_p2pkh(h160) for h160 in hash160_list]
        return list(zip(address_list, sig_type_list))
