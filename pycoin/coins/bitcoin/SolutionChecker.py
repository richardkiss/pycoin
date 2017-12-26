import io

from hashlib import sha256

from .ScriptTools import BitcoinScriptTools
from .VM import BitcoinVM

from ...encoding.hash import double_sha256
from ...encoding.bytes32 import from_bytes_32
from ...intbytes import byte2int, indexbytes

from ..SolutionChecker import SolutionChecker, ScriptError
from pycoin.satoshi import errno

from ...serialize.bitcoin_streamer import (
    stream_struct, stream_bc_string
)

from pycoin.satoshi.flags import (
    SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
    VERIFY_P2SH, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_SIGPUSHONLY, VERIFY_CLEANSTACK,
    VERIFY_WITNESS, VERIFY_MINIMALIF, VERIFY_WITNESS_PUBKEYTYPE
)


V0_len20_prefix = BitcoinScriptTools.compile("OP_DUP OP_HASH160")
V0_len20_postfix = BitcoinScriptTools.compile("OP_EQUALVERIFY OP_CHECKSIG")
OP_EQUAL = BitcoinScriptTools.int_for_opcode("OP_EQUAL")
OP_HASH160 = BitcoinScriptTools.int_for_opcode("OP_HASH160")

OP_0 = BitcoinScriptTools.int_for_opcode("OP_0")
OP_1 = BitcoinScriptTools.int_for_opcode("OP_1")
OP_16 = BitcoinScriptTools.int_for_opcode("OP_16")


ZERO32 = b'\0' * 32


class TxContext(object):
    pass


class BitcoinSolutionChecker(SolutionChecker):
    VM = BitcoinVM
    ScriptTools = BitcoinScriptTools

    def __init__(self, tx):
        self.tx = tx
        # self.sighash_cache = {}

    @classmethod
    def is_pay_to_script_hash(class_, script_public_key):
        return (len(script_public_key) == 23 and byte2int(script_public_key) == OP_HASH160 and
                indexbytes(script_public_key, -1) == OP_EQUAL)

    @classmethod
    def script_hash_from_script(class_, puzzle_script):
        if class_.is_pay_to_script_hash(puzzle_script):
            return puzzle_script[2:-1]
        return False

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

    def make_sighash_f(self, tx_in_idx):

        def sig_for_hash_type_f(hash_type, sig_blobs, vm):
            script = vm.script[vm.begin_code_hash:]
            for sig_blob in sig_blobs:
                script = self._delete_signature(script, sig_blob)
            return self.signature_hash(script, tx_in_idx, hash_type)

        return sig_for_hash_type_f

    def solution_script_to_stack(self, tx_context, flags, traceback_f):
        if flags & VERIFY_SIGPUSHONLY:
            self.check_script_push_only(tx_context.solution_script)

        # never use VERIFY_MINIMALIF or VERIFY_WITNESS_PUBKEYTYPE except in segwit
        f1 = flags & ~(VERIFY_MINIMALIF | VERIFY_WITNESS_PUBKEYTYPE)

        vm = self.VM(tx_context.solution_script, tx_context, self.make_sighash_f(tx_context.tx_in_idx), f1)

        vm.is_solution_script = True
        vm.traceback_f = traceback_f

        solution_stack = vm.eval_script()
        return solution_stack

    def check_solution(self, tx_context, flags=None, traceback_f=None):
        """
        tx_context: information about the transaction that the VM may need
        flags: gives the VM hints about which additional constraints to check
        """

        if flags is None:
            flags = VERIFY_P2SH | VERIFY_WITNESS

        solution_stack = self.solution_script_to_stack(tx_context, flags=flags, traceback_f=traceback_f)

        stack, solution_stack = self._check_solution(tx_context, solution_stack, flags, traceback_f)

        had_witness = False
        if flags & VERIFY_WITNESS:
            had_witness = self.check_witness(tx_context, flags, traceback_f)

        had_p2sh = False
        if flags & VERIFY_P2SH:
            had_p2sh = self.check_p2sh(tx_context, solution_stack, flags, traceback_f)

        if had_p2sh:
            return

        if flags & VERIFY_CLEANSTACK and len(stack) != 1:
            raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

        if (flags & VERIFY_WITNESS) and not had_witness and len(tx_context.witness_solution_stack) > 0:
            raise ScriptError("witness unexpected", errno.WITNESS_UNEXPECTED)

    def _check_solution(self, tx_context, solution_stack, flags, traceback_f):
        puzzle_script = tx_context.puzzle_script

        # never use VERIFY_MINIMALIF or VERIFY_WITNESS_PUBKEYTYPE except in segwit
        f1 = flags & ~(VERIFY_MINIMALIF | VERIFY_WITNESS_PUBKEYTYPE)

        vm = self.VM(puzzle_script, tx_context, self.make_sighash_f(tx_context.tx_in_idx), f1, initial_stack=solution_stack[:])

        vm.is_solution_script = False
        vm.traceback_f = traceback_f

        # work on a copy of the solution stack
        stack = vm.eval_script()
        if len(stack) == 0 or not vm.bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)

        return stack, solution_stack

    def check_p2sh(self, tx_context, solution_stack, flags, traceback_f):
        if self.is_pay_to_script_hash(tx_context.puzzle_script):
            self._check_p2sh(tx_context, solution_stack[:-1], solution_stack[-1], flags=flags, traceback_f=traceback_f)
            return True
        return False

    def _check_p2sh(self, tx_context, solution_blob, puzzle_script, flags, traceback_f):
        self.check_script_push_only(tx_context.solution_script)
        solution_script = self.ScriptTools.compile_push_data_list(solution_blob)
        flags &= ~VERIFY_P2SH
        p2sh_tx_context = TxContext()
        p2sh_tx_context.puzzle_script = puzzle_script
        p2sh_tx_context.solution_script = solution_script
        p2sh_tx_context.witness_solution_stack = tx_context.witness_solution_stack
        p2sh_tx_context.sequence = tx_context.sequence
        p2sh_tx_context.version = tx_context.version
        p2sh_tx_context.lock_time = tx_context.lock_time
        p2sh_tx_context.tx_in_idx = tx_context.tx_in_idx
        self.check_solution(p2sh_tx_context, flags=flags, traceback_f=traceback_f)

    def check_script_push_only(self, script):
        scriptStreamer = self.VM.ScriptStreamer
        pc = 0
        while pc < len(script):
            opcode, data, pc = scriptStreamer.get_opcode(script, pc)
            if opcode not in scriptStreamer.data_opcodes:
                raise ScriptError("signature has non-push opcodes", errno.SIG_PUSHONLY)

    def _puzzle_script_for_len20_segwit(self, witness_program):
        return V0_len20_prefix + self.ScriptTools.compile_push_data_list(
            [witness_program]) + V0_len20_postfix

    def check_witness_program_v0(self, witness_solution_stack, witness_program, tx_context, flags):
        size = len(witness_program)
        if size == 32:
            if len(witness_solution_stack) == 0:
                raise ScriptError("witness program witness empty", errno.WITNESS_PROGRAM_WITNESS_EMPTY)
            puzzle_script = witness_solution_stack[-1]
            if sha256(puzzle_script).digest() != witness_program:
                raise ScriptError("witness program mismatch", errno.WITNESS_PROGRAM_MISMATCH)
            stack = list(witness_solution_stack[:-1])
        elif size == 20:
            # special case for pay-to-pubkeyhash; signature + pubkey in witness
            if len(witness_solution_stack) != 2:
                raise ScriptError("witness program mismatch", errno.WITNESS_PROGRAM_MISMATCH)
            puzzle_script = self._puzzle_script_for_len20_segwit(witness_program)
            stack = list(witness_solution_stack)
        else:
            raise ScriptError("witness program wrong length", errno.WITNESS_PROGRAM_WRONG_LENGTH)
        return stack, puzzle_script

    def check_witness_program(self, version, witness_program, tx_context, flags, traceback_f):
        if version == 0:
            stack, puzzle_script = self.check_witness_program_v0(
                tx_context.witness_solution_stack, witness_program, flags, tx_context)
        elif flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
            raise ScriptError(
                "this version witness program not yet supported", errno.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        else:
            return

        def witness_signature_for_hash_type(hash_type, sig_blobs, vm):
            return self.signature_for_hash_type_segwit(
                vm.script[vm.begin_code_hash:], tx_context.tx_in_idx, hash_type)

        vm = self.VM(
            puzzle_script, tx_context, witness_signature_for_hash_type, flags, initial_stack=stack)
        vm.traceback_f = traceback_f
        vm.is_solution_script = False

        for s in stack:
            if len(s) > vm.MAX_BLOB_LENGTH:
                raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)

        stack = vm.eval_script()

        if len(stack) == 0 or not vm.bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)

        if len(stack) != 1:
            raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

    def witness_program_version(self, script):
        size = len(script)
        if size < 4 or size > 42:
            return None
        first_opcode = byte2int(script)
        if indexbytes(script, 1) + 2 != size:
            return None
        if first_opcode == OP_0:
            return 0
        if OP_1 <= first_opcode <= OP_16:
            return first_opcode - OP_1 + 1
        return None

    def check_witness(self, tx_context, flags, traceback_f):
        witness_version = self.witness_program_version(tx_context.puzzle_script)
        had_witness = False
        if witness_version is not None:
            had_witness = True
            witness_program = tx_context.puzzle_script[2:]
            if len(tx_context.solution_script) > 0:
                err = errno.WITNESS_MALLEATED if flags & VERIFY_P2SH else errno.WITNESS_MALLEATED_P2SH
                raise ScriptError("script sig is not blank on segwit input", err)
            self.check_witness_program(
                witness_version, witness_program, tx_context, flags, traceback_f)
        return had_witness

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

    def signature_hash(self, tx_out_script, unsigned_txs_out_idx, hash_type):
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
            # original code; note that higher level functions for signing
            # new transactions (e.g., is_signature_ok and sign_tx_in)
            # check to make sure we never get here (or at least they
            # should)
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

    def hash_prevouts(self, hash_type):
        if hash_type & SIGHASH_ANYONECANPAY:
            return ZERO32
        f = io.BytesIO()
        for tx_in in self.tx.txs_in:
            f.write(tx_in.previous_hash)
            stream_struct("L", f, tx_in.previous_index)
        return double_sha256(f.getvalue())

    def hash_sequence(self, hash_type):
        if (
                (hash_type & SIGHASH_ANYONECANPAY) or
                ((hash_type & 0x1f) == SIGHASH_SINGLE) or
                ((hash_type & 0x1f) == SIGHASH_NONE)
        ):
            return ZERO32

        f = io.BytesIO()
        for tx_in in self.tx.txs_in:
            stream_struct("L", f, tx_in.sequence)
        return double_sha256(f.getvalue())

    def hash_outputs(self, hash_type, tx_in_idx):
        txs_out = self.tx.txs_out
        if hash_type & 0x1f == SIGHASH_SINGLE:
            if tx_in_idx >= len(txs_out):
                return ZERO32
            txs_out = txs_out[tx_in_idx:tx_in_idx+1]
        elif hash_type & 0x1f == SIGHASH_NONE:
            return ZERO32
        f = io.BytesIO()
        for tx_out in txs_out:
            stream_struct("Q", f, tx_out.coin_value)
            self.ScriptTools.write_push_data([tx_out.script], f)
        return double_sha256(f.getvalue())

    def segwit_signature_preimage(self, script, tx_in_idx, hash_type):
        f = io.BytesIO()
        stream_struct("L", f, self.tx.version)
        # calculate hash prevouts
        f.write(self.hash_prevouts(hash_type))
        f.write(self.hash_sequence(hash_type))
        tx_in = self.tx.txs_in[tx_in_idx]
        f.write(tx_in.previous_hash)
        stream_struct("L", f, tx_in.previous_index)
        tx_out = self.tx.unspents[tx_in_idx]
        stream_bc_string(f, script)
        stream_struct("Q", f, tx_out.coin_value)
        stream_struct("L", f, tx_in.sequence)
        f.write(self.hash_outputs(hash_type, tx_in_idx))
        stream_struct("L", f, self.tx.lock_time)
        stream_struct("L", f, hash_type)
        return f.getvalue()

    def signature_for_hash_type_segwit(self, script, tx_in_idx, hash_type):
        return from_bytes_32(double_sha256(self.segwit_signature_preimage(script, tx_in_idx, hash_type)))

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
