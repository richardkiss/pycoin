import io

from hashlib import sha256

from ...encoding.hash import double_sha256
from ...encoding.bytes32 import from_bytes_32
from ...intbytes import byte2int, indexbytes

from ..SolutionChecker import SolutionChecker, ScriptError
from pycoin.satoshi import errno

from pycoin.satoshi.satoshi_struct import stream_struct
from pycoin.satoshi.satoshi_string import stream_satoshi_string

from pycoin.satoshi.flags import (
    SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
    VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, VERIFY_CLEANSTACK, VERIFY_WITNESS
)

from .ScriptTools import BitcoinScriptTools


ZERO32 = b'\0' * 32


class SegwitChecker(SolutionChecker):
    # you must set VM
    # you must set ScriptTools

    V0_len20_prefix = BitcoinScriptTools.compile("OP_DUP OP_HASH160")
    V0_len20_postfix = BitcoinScriptTools.compile("OP_EQUALVERIFY OP_CHECKSIG")

    OP_0 = BitcoinScriptTools.int_for_opcode("OP_0")
    OP_1 = BitcoinScriptTools.int_for_opcode("OP_1")
    OP_16 = BitcoinScriptTools.int_for_opcode("OP_16")

    def _make_witness_sighash_f(self, tx_in_idx):

        def witness_signature_for_hash_type(hash_type, sig_blobs, vm):
            return self._signature_for_hash_type_segwit(
                vm.script[vm.begin_code_hash:], tx_in_idx, hash_type)

        return witness_signature_for_hash_type

    def _puzzle_script_for_len20_segwit(self, witness_program):
        return self.V0_len20_prefix + self.ScriptTools.compile_push_data_list(
            [witness_program]) + self.V0_len20_postfix

    def _check_witness_program_v0(self, witness_solution_stack, witness_program):
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

    def _witness_program_version(self, script):
        size = len(script)
        if size < 4 or size > 42:
            return None
        first_opcode = byte2int(script)
        if indexbytes(script, 1) + 2 != size:
            return None
        if first_opcode == self.OP_0:
            return 0
        if self.OP_1 <= first_opcode <= self.OP_16:
            return first_opcode - self.OP_1 + 1
        return None

    def _hash_prevouts(self, hash_type):
        if hash_type & SIGHASH_ANYONECANPAY:
            return ZERO32
        f = io.BytesIO()
        for tx_in in self.tx.txs_in:
            f.write(tx_in.previous_hash)
            stream_struct("L", f, tx_in.previous_index)
        return double_sha256(f.getvalue())

    def _hash_sequence(self, hash_type):
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

    def _hash_outputs(self, hash_type, tx_in_idx):
        txs_out = self.tx.txs_out
        if hash_type & 0x1f == SIGHASH_SINGLE:
            if tx_in_idx >= len(txs_out):
                return ZERO32
            txs_out = txs_out[tx_in_idx:tx_in_idx+1]
        elif hash_type & 0x1f == SIGHASH_NONE:
            return ZERO32
        f = io.BytesIO()
        for tx_out in txs_out:
            stream_struct("QS", f, tx_out.coin_value, tx_out.script)
        return double_sha256(f.getvalue())

    def _segwit_signature_preimage(self, script, tx_in_idx, hash_type):
        f = io.BytesIO()
        stream_struct("L", f, self.tx.version)
        # calculate hash prevouts
        f.write(self._hash_prevouts(hash_type))
        f.write(self._hash_sequence(hash_type))
        tx_in = self.tx.txs_in[tx_in_idx]
        f.write(tx_in.previous_hash)
        stream_struct("L", f, tx_in.previous_index)
        tx_out = self.tx.unspents[tx_in_idx]
        stream_satoshi_string(f, script)
        stream_struct("Q", f, tx_out.coin_value)
        stream_struct("L", f, tx_in.sequence)
        f.write(self._hash_outputs(hash_type, tx_in_idx))
        stream_struct("L", f, self.tx.lock_time)
        stream_struct("L", f, hash_type)
        return f.getvalue()

    def _signature_for_hash_type_segwit(self, script, tx_in_idx, hash_type):
        return from_bytes_32(double_sha256(self._segwit_signature_preimage(script, tx_in_idx, hash_type)))

    def witness_program_tuple(self, tx_context, puzzle_script, solution_stack, flags, is_p2sh):
        if not flags & VERIFY_WITNESS:
            return

        witness_version = self._witness_program_version(puzzle_script)
        if witness_version is None:
            if len(tx_context.witness_solution_stack) > 0:
                raise ScriptError("witness unexpected", errno.WITNESS_UNEXPECTED)
        else:
            witness_program = puzzle_script[2:]
            if len(solution_stack) > 0:
                err = errno.WITNESS_MALLEATED_P2SH if is_p2sh else errno.WITNESS_MALLEATED
                raise ScriptError("script sig is not blank on segwit input", err)

            for s in tx_context.witness_solution_stack:
                if len(s) > self.VM.MAX_BLOB_LENGTH:
                    raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)

            if witness_version == 0:
                stack, puzzle_script = self._check_witness_program_v0(
                    tx_context.witness_solution_stack, witness_program)
                sighash_f = self._make_witness_sighash_f(tx_context.tx_in_idx)
                return puzzle_script, stack, flags | VERIFY_CLEANSTACK, sighash_f
            elif flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
                raise ScriptError(
                    "this version witness program not yet supported", errno.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
