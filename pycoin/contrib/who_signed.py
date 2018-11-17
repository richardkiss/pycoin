from ..encoding.sec import is_sec, public_pair_to_hash160_sec, sec_to_public_pair, EncodingError

from pycoin.coins.SolutionChecker import ScriptError
from pycoin.satoshi.checksigops import parse_signature_blob
from pycoin.satoshi.der import UnexpectedDER


class WhoSigned(object):
    def __init__(self, script_tools, address_api, generator):
        self._script_tools = script_tools
        self._address = address_api
        self._generator = generator

    def solution_blobs(self, tx, tx_in_idx):
        """
        This iterator yields data blobs that appear in the the last solution_script or the witness.
        """
        sc = tx.SolutionChecker(tx)
        tx_context = sc.tx_context_for_idx(tx_in_idx)
        # set solution_stack in case there are no results from puzzle_and_solution_iterator
        solution_stack = []
        for puzzle_script, solution_stack, flags, sighash_f in sc.puzzle_and_solution_iterator(tx_context):
            pass
            # we only care about the last one
        for s in solution_stack:
            yield s

    def extract_signatures(self, tx, tx_in_idx):
        sc = tx.SolutionChecker(tx)
        tx_context = sc.tx_context_for_idx(tx_in_idx)
        # set solution_stack in case there are no results from puzzle_and_solution_iterator
        solution_stack = []
        for puzzle_script, solution_stack, flags, sighash_f in sc.puzzle_and_solution_iterator(tx_context):
            pass
            # we only care about the last one

        vm = sc.VM(puzzle_script, tx_context, sighash_f, flags=flags, initial_stack=solution_stack[:])
        for data in self.solution_blobs(tx, tx_in_idx):
            try:
                sig_pair, sig_type = parse_signature_blob(data)
                sig_hash = sighash_f(sig_type, sig_blobs=[], vm=vm)
                yield (data, sig_hash)
            except (ValueError, TypeError, UnexpectedDER, ScriptError):
                continue

    def extract_secs(self, tx, tx_in_idx):
        """
        For a given script solution, iterate yield its sec blobs
        """
        sc = tx.SolutionChecker(tx)
        tx_context = sc.tx_context_for_idx(tx_in_idx)
        # set solution_stack in case there are no results from puzzle_and_solution_iterator
        solution_stack = []
        for puzzle_script, solution_stack, flags, sighash_f in sc.puzzle_and_solution_iterator(tx_context):
            for opcode, data, pc, new_pc in self._script_tools.get_opcodes(puzzle_script):
                if data and is_sec(data):
                    yield data
            for data in solution_stack:
                if is_sec(data):
                    yield data

    def public_pairs_for_script(self, tx, tx_in_idx, generator):
        """
        For a given script, iterate over and pull out public pairs encoded as sec values.
        """
        public_pairs = []
        for sec in self.extract_secs(tx, tx_in_idx):
            try:
                public_pairs.append(sec_to_public_pair(sec, generator))
            except EncodingError:
                pass
        return public_pairs

    def public_pairs_signed(self, tx, tx_in_idx):
        signed_by = []

        public_pairs = self.public_pairs_for_script(tx, tx_in_idx, self._generator)

        for signature, sig_hash in self.extract_signatures(tx, tx_in_idx):
            sig_pair, sig_type = parse_signature_blob(signature)

            for public_pair in public_pairs:
                if self._generator.verify(public_pair, sig_hash, sig_pair):
                    signed_by.append((public_pair, sig_pair, sig_type))
        return signed_by

    def who_signed_tx(self, tx, tx_in_idx):
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
        address_list = [self._address.for_p2pkh(h160) for h160 in hash160_list]
        return list(zip(address_list, sig_type_list))
