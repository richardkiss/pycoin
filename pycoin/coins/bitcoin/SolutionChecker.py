from hashlib import sha256

from ...intbytes import byte2int, indexbytes

from ...tx.script.BaseSolutionChecker import SolutionChecker, VMContext
from ...tx.script import errno
from ...tx.script import ScriptError
from ...tx.script.Stack import Stack

from .ScriptTools import BitcoinScriptTools
from .VM import BitcoinVM

from ...tx.script.flags import (
    VERIFY_P2SH, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
)


def make_solution_checker():
    V0_len20_prefix = BitcoinScriptTools.compile("OP_DUP OP_HASH160")
    V0_len20_postfix = BitcoinScriptTools.compile("OP_EQUALVERIFY OP_CHECKSIG")
    OP_EQUAL = BitcoinScriptTools.int_for_opcode("OP_EQUAL")
    OP_HASH160 = BitcoinScriptTools.int_for_opcode("OP_HASH160")

    OP_0 = BitcoinScriptTools.int_for_opcode("OP_0")
    OP_1 = BitcoinScriptTools.int_for_opcode("OP_1")
    OP_16 = BitcoinScriptTools.int_for_opcode("OP_16")

    class BitcoinSolutionChecker(SolutionChecker):
        VM = BitcoinVM

        @classmethod
        def is_pay_to_script_hash(class_, script_public_key):
            return (len(script_public_key) == 23 and byte2int(script_public_key) == OP_HASH160 and
                    indexbytes(script_public_key, -1) == OP_EQUAL)

        @classmethod
        def _puzzle_script_for_len20_segwit(class_, witness_program):
            return V0_len20_prefix + class_.VM.dataCodec.compile_push_data(
                witness_program) + V0_len20_postfix

        @classmethod
        def check_witness_program_v0(class_, witness_solution_stack, witness_program, tx_context, flags):
            l = len(witness_program)
            if l == 32:
                if len(witness_solution_stack) == 0:
                    raise ScriptError("witness program witness empty", errno.WITNESS_PROGRAM_WITNESS_EMPTY)
                puzzle_script = witness_solution_stack[-1]
                if sha256(puzzle_script).digest() != witness_program:
                    raise ScriptError("witness program mismatch", errno.WITNESS_PROGRAM_MISMATCH)
                stack = Stack(witness_solution_stack[:-1])
            elif l == 20:
                # special case for pay-to-pubkeyhash; signature + pubkey in witness
                if len(witness_solution_stack) != 2:
                    raise ScriptError("witness program mismatch", errno.WITNESS_PROGRAM_MISMATCH)
                puzzle_script = class_._puzzle_script_for_len20_segwit(witness_program)
                stack = Stack(witness_solution_stack)
            else:
                raise ScriptError("witness program wrong length", errno.WITNESS_PROGRAM_WRONG_LENGTH)
            return stack, puzzle_script

        @classmethod
        def check_witness_program(
                class_, version, witness_program, tx_context, flags, traceback_f):
            if version == 0:
                stack, puzzle_script = class_.check_witness_program_v0(
                    tx_context.witness_solution_stack, witness_program, flags, tx_context)
            elif flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
                raise ScriptError(
                    "this version witness program not yet supported", errno.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
            else:
                return

            vm = class_.VM()
            vm_context = VMContext()
            vm_context.flags = flags
            vm_context.signature_for_hash_type_f = tx_context.signature_for_hash_type_f.witness
            vm_context.traceback_f = traceback_f

            for s in stack:
                if len(s) > vm.MAX_BLOB_LENGTH:
                    raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)

            vm.eval_script(puzzle_script, tx_context, vm_context, initial_stack=stack)

            if len(stack) == 0 or not class_.VM.bool_from_script_bytes(stack[-1]):
                raise ScriptError("eval false", errno.EVAL_FALSE)

            if len(stack) != 1:
                raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

        @classmethod
        def witness_program_version(class_, script):
            l = len(script)
            if l < 4 or l > 42:
                return None
            first_opcode = byte2int(script)
            if indexbytes(script, 1) + 2 != l:
                return None
            if first_opcode == OP_0:
                return 0
            if OP_1 <= first_opcode <= OP_16:
                return first_opcode - OP_1 + 1
            return None

        @classmethod
        def check_witness(class_, tx_context, flags, traceback_f):
            witness_version = class_.witness_program_version(tx_context.puzzle_script)
            had_witness = False
            if witness_version is not None:
                had_witness = True
                witness_program = tx_context.puzzle_script[2:]
                if len(tx_context.solution_script) > 0:
                    err = errno.WITNESS_MALLEATED if flags & VERIFY_P2SH else errno.WITNESS_MALLEATED_P2SH
                    raise ScriptError("script sig is not blank on segwit input", err)
                class_.check_witness_program(
                    witness_version, witness_program, tx_context, flags, traceback_f)
            return had_witness

    return BitcoinSolutionChecker


BitcoinSolutionChecker = make_solution_checker()
