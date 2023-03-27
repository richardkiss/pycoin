from ..encoding.sec import is_sec, public_pair_to_hash160_sec, sec_to_public_pair, EncodingError

from pycoin.coins.SolutionChecker import ScriptError
from pycoin.intbytes import byte2int
from pycoin.satoshi.checksigops import parse_signature_blob
from pycoin.satoshi.der import UnexpectedDER


class WhoSigned(object):
    def __init__(self, script_tools, address_api, generator):
        self._script_tools = script_tools
        self._address = address_api
        self._generator = generator
        for _ in "CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY".split():
            setattr(self, "OP_%s" % _, byte2int(self._script_tools.compile('OP_%s' % _)))

    def solution_blobs(self, tx, tx_in_idx):
        """
        This iterator yields data blobs that appear in the last solution_script or the witness.
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

    def _handle_checksig(self, vmc):
        s = list(vmc.stack)
        sec_blob = sig_blob = None
        sig_hash = 0
        try:
            sec_blob = vmc.pop()
            sig_blob = vmc.pop()
            try:
                sig_pair, sig_type = parse_signature_blob(sig_blob)
                sig_hash = vmc.signature_for_hash_type_f(sig_type, [sig_blob], vmc)
            except ValueError:
                pass
        except (IndexError, ValueError):
            pass

        return ([sec_blob], [(sig_blob, sig_hash)])

    def _handle_checkmultisig(self, vmc):
        sec_blobs = []
        sig_blobs = []
        s = list(vmc.stack)
        try:
            key_count = vmc.pop_int()
            while key_count > 0:
                key_count -= 1
                sec_blobs.append(vmc.pop())

            signature_count = vmc.pop_int()
            while signature_count > 0:
                signature_count -= 1
                sig_blob = vmc.pop()
                sig_hash = 0
                try:
                    sig_pair, sig_type = parse_signature_blob(sig_blob)
                    sig_hash = vmc.signature_for_hash_type_f(sig_type, [sig_blob], vmc)
                except ValueError:
                    pass
                sig_blobs.append((sig_blob, sig_hash))
        except IndexError:
            pass
        vmc.stack = s
        return (sec_blobs, sig_blobs)

    def extract_secs(self, tx, tx_in_idx):
        for sec_blobs, sig_and_hash_pairs in self.extract_secs_and_signatures(tx, tx_in_idx):
            for blob in sec_blobs:
                yield blob

    def extract_signatures(self, tx, tx_in_idx):
        for sec_blobs, sig_and_hash_pairs in self.extract_secs_and_signatures(tx, tx_in_idx):
            for sig_blob, sig_hash in sig_and_hash_pairs:
                try:
                    sig_pair, sig_type = parse_signature_blob(sig_blob)
                    yield (sig_blob, sig_hash)
                except (ValueError, TypeError, UnexpectedDER, ScriptError):
                    continue

    def extract_secs_and_signatures(self, tx, tx_in_idx):
        """
        List[Tuple[List[bytes], List[Tuple[bytes, SigHashFType]]]
        """
        sc = tx.SolutionChecker(tx)
        tx_context = sc.tx_context_for_idx(tx_in_idx)

        blobs_for_sig_ops = []
        def traceback_f(opcode, data, pc, vmc):
            if opcode in (self.OP_CHECKSIG, self.OP_CHECKSIGVERIFY):
                blobs_for_sig_ops.append(self._handle_checksig(vmc))
            if opcode in (self.OP_CHECKMULTISIG, self.OP_CHECKMULTISIGVERIFY):
                blobs_for_sig_ops.append(self._handle_checkmultisig(vmc))
            return

        try:
            sc.check_solution(tx_context, traceback_f=traceback_f)
        except ScriptError:
            pass

        return blobs_for_sig_ops

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
