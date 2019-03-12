from .ScriptTools import BitcoinScriptTools
from .VM import BitcoinVM

from ...encoding.bytes32 import from_bytes_32

from pycoin.satoshi import errno
from pycoin.satoshi.flags import (
    SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
    VERIFY_P2SH, VERIFY_SIGPUSHONLY, VERIFY_CLEANSTACK,
    VERIFY_WITNESS, VERIFY_MINIMALIF, VERIFY_WITNESS_PUBKEYTYPE
)

from .SegwitChecker import SegwitChecker
from .P2SChecker import P2SChecker


class TxContext(object):
    pass


class BitcoinSolutionChecker(SegwitChecker, P2SChecker):
    VM = BitcoinVM
    ScriptTools = BitcoinScriptTools

    DEFAULT_FLAGS = VERIFY_P2SH | VERIFY_WITNESS

    def __init__(self, tx):
        self.tx = tx
        # self.sighash_cache = {}

    def _delete_signature(self, script, sig_blob):
        """
        Returns a script with the given subscript removed. The subscript
        must appear in the main script aligned to opcode boundaries for it
        to be removed.
        """
        subscript = self.ScriptTools.compile_push_data_list([sig_blob])
        new_script = bytearray()
        pc = 0
        for opcode, data, pc, new_pc in self.ScriptTools.get_opcodes(script):
            section = script[pc:new_pc]
            if section != subscript:
                new_script.extend(section)
        return bytes(new_script)

    def _make_sighash_f(self, tx_in_idx):

        def sig_for_hash_type_f(hash_type, sig_blobs, vm):
            script = vm.script[vm.begin_code_hash:]
            for sig_blob in sig_blobs:
                script = self._delete_signature(script, sig_blob)
            return self._signature_hash(script, tx_in_idx, hash_type)

        return sig_for_hash_type_f

    def _solution_script_to_stack(self, tx_context, flags, traceback_f):
        if flags & VERIFY_SIGPUSHONLY:
            self._check_script_push_only(tx_context.solution_script)

        # never use VERIFY_MINIMALIF or VERIFY_WITNESS_PUBKEYTYPE except in segwit
        f1 = flags & ~(VERIFY_MINIMALIF | VERIFY_WITNESS_PUBKEYTYPE)

        vm = self.VM(tx_context.solution_script, tx_context, self._make_sighash_f(tx_context.tx_in_idx), f1)

        vm.is_solution_script = True
        vm.traceback_f = traceback_f

        solution_stack = vm.eval_script()
        return solution_stack

    def _check_script_push_only(self, script):
        scriptStreamer = self.VM.ScriptStreamer
        pc = 0
        while pc < len(script):
            opcode, data, pc, is_ok = scriptStreamer.get_opcode(script, pc)
            if opcode not in scriptStreamer.data_opcodes:
                raise self.ScriptError("signature has non-push opcodes", errno.SIG_PUSHONLY)

    def _tx_in_for_idx(self, idx, tx_in, tx_out_script, unsigned_txs_out_idx):
        if idx == unsigned_txs_out_idx:
            return self.tx.TxIn(tx_in.previous_hash, tx_in.previous_index, tx_out_script, tx_in.sequence)
        return self.tx.TxIn(tx_in.previous_hash, tx_in.previous_index, b'', tx_in.sequence)

    @classmethod
    def delete_subscript(class_, script, subscript):
        """
        Returns a script with the given subscript removed. The subscript
        must appear in the main script aligned to opcode boundaries for it
        to be removed.
        """
        new_script = bytearray()
        pc = 0
        for opcode, data, pc, new_pc in class_.ScriptTools.get_opcodes(script):
            section = script[pc:new_pc]
            if section != subscript:
                new_script.extend(section)
        return bytes(new_script)

    def _signature_hash(self, tx_out_script, unsigned_txs_out_idx, hash_type):
        """
        Return the canonical hash for a transaction. We need to
        remove references to the signature, since it's a signature
        of the hash before the signature is applied.

        :param tx_out_script: the script the coins for unsigned_txs_out_idx are coming from
        :param unsigned_txs_out_idx: where to put the tx_out_script
        :param hash_type: one of SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL,
            optionally bitwise or'ed with SIGHASH_ANYONECANPAY
        """

        # In case concatenating two scripts ends up with two codeseparators,
        # or an extra one at the end, this prevents all those possible incompatibilities.
        tx_out_script = self.delete_subscript(tx_out_script, self.ScriptTools.compile("OP_CODESEPARATOR"))

        # blank out other inputs' signatures
        txs_in = [self._tx_in_for_idx(i, tx_in, tx_out_script, unsigned_txs_out_idx)
                  for i, tx_in in enumerate(self.tx.txs_in)]
        txs_out = self.tx.txs_out

        # Blank out some of the outputs
        if (hash_type & 0x1f) == SIGHASH_NONE:
            # Wildcard payee
            txs_out = []

            # Let the others update at will
            for i in range(len(txs_in)):
                if i != unsigned_txs_out_idx:
                    txs_in[i].sequence = 0

        elif (hash_type & 0x1f) == SIGHASH_SINGLE:
            # This preserves the ability to validate existing legacy
            # transactions which followed a buggy path in Satoshi's
            # original code.
            if unsigned_txs_out_idx >= len(txs_out):
                # This should probably be moved to a constant, but the
                # likelihood of ever getting here is already really small
                # and getting smaller
                return (1 << 248)

            # Only lock in the txout payee at same index as txin; delete
            # any outputs after this one and set all outputs before this
            # one to "null" (where "null" means an empty script and a
            # value of -1)
            txs_out = [self.tx.TxOut(0xffffffffffffffff, b'')] * unsigned_txs_out_idx
            txs_out.append(self.tx.txs_out[unsigned_txs_out_idx])

            # Let the others update at will
            for i in range(len(txs_in)):
                if i != unsigned_txs_out_idx:
                    txs_in[i].sequence = 0

        # Blank out other inputs completely, not recommended for open transactions
        if hash_type & SIGHASH_ANYONECANPAY:
            txs_in = [txs_in[unsigned_txs_out_idx]]

        tmp_tx = self.tx.__class__(self.tx.version, txs_in, txs_out, self.tx.lock_time)
        return from_bytes_32(tmp_tx.hash(hash_type=hash_type))

    def tx_context_for_idx(self, tx_in_idx):
        """
        solution_script: alleged solution to the puzzle_script
        puzzle_script: the script protecting the coins
        """
        tx_in = self.tx.txs_in[tx_in_idx]

        tx_context = TxContext()
        tx_context.lock_time = self.tx.lock_time
        tx_context.version = self.tx.version
        tx_context.puzzle_script = b'' if self.tx.missing_unspent(tx_in_idx) else self.tx.unspents[tx_in_idx].script
        tx_context.solution_script = tx_in.script
        tx_context.witness_solution_stack = tx_in.witness
        tx_context.sequence = tx_in.sequence
        tx_context.tx_in_idx = tx_in_idx
        return tx_context

    def check_solution(self, tx_context, flags=None, traceback_f=None):
        """
        tx_context: information about the transaction that the VM may need
        flags: gives the VM hints about which additional constraints to check
        """

        for t in self.puzzle_and_solution_iterator(tx_context, flags=flags, traceback_f=traceback_f):
            puzzle_script, solution_stack, flags, sighash_f = t

            vm = self.VM(puzzle_script, tx_context, sighash_f, flags=flags, initial_stack=solution_stack[:])

            vm.is_solution_script = False
            vm.traceback_f = traceback_f

            stack = vm.eval_script()
            if len(stack) == 0 or not vm.bool_from_script_bytes(stack[-1]):
                raise self.ScriptError("eval false", errno.EVAL_FALSE)

        if flags & VERIFY_CLEANSTACK and len(stack) != 1:
            raise self.ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

    def puzzle_and_solution_iterator(self, tx_context, flags=None, traceback_f=None):
        if flags is None:
            flags = self.DEFAULT_FLAGS

        solution_stack = self._solution_script_to_stack(tx_context, flags=flags, traceback_f=traceback_f)
        puzzle_script = tx_context.puzzle_script

        flags_1 = flags & ~(VERIFY_MINIMALIF | VERIFY_WITNESS_PUBKEYTYPE)

        sighash_f = self._make_sighash_f(tx_context.tx_in_idx)
        yield puzzle_script, solution_stack, flags_1, sighash_f

        p2sh_tuple = self.p2s_program_tuple(tx_context, puzzle_script, solution_stack, flags_1, sighash_f)
        if p2sh_tuple:
            yield p2sh_tuple
            puzzle_script, solution_stack = p2sh_tuple[:2]

        is_p2sh = p2sh_tuple is not None
        witness_tuple = self.witness_program_tuple(tx_context, puzzle_script, solution_stack, flags, is_p2sh)
        if witness_tuple:
            yield witness_tuple
