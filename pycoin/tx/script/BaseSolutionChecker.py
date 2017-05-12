from hashlib import sha256

from .flags import (
    VERIFY_P2SH, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_SIGPUSHONLY, VERIFY_CLEANSTACK,
    VERIFY_WITNESS, VERIFY_MINIMALIF, VERIFY_WITNESS_PUBKEYTYPE
)

from .BaseVM import VM

from ...intbytes import byte2int, indexbytes

from . import ScriptError
from . import errno
from . import opcodes

from .Stack import Stack


class TxContext(object):
    pass


class VMContext(object):
    pass


class SolutionChecker(object):
    VM = VM

    @staticmethod
    def is_pay_to_script_hash(script_public_key):
        return (len(script_public_key) == 23 and byte2int(script_public_key) == opcodes.OP_HASH160 and
                indexbytes(script_public_key, -1) == opcodes.OP_EQUAL)

    @classmethod
    def get_opcode(class_, script, pc):
        return class_.VM.ScriptCodec.get_opcode(script, pc)

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
    def _puzzle_script_for_len20_segwit(class_, witness_program):
        pass

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

    @staticmethod
    def witness_program_version(script):
        l = len(script)
        if l < 4 or l > 42:
            return None
        first_opcode = byte2int(script)
        if indexbytes(script, 1) + 2 != l:
            return None
        if first_opcode == opcodes.OP_0:
            return 0
        if opcodes.OP_1 <= first_opcode <= opcodes.OP_16:
            return first_opcode - opcodes.OP_1 + 1
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

    @classmethod
    def check_solution(class_, tx_context, flags, traceback_f=None):
        """
        solution_script: alleged solution to the puzzle_script
        puzzle_script: the script protecting the coins
        tx_context: information about the transaction that the VM may need
        flags: gives the VM hints about which additional constraints to check
        """
        if flags is None:
            flags = VERIFY_P2SH | VERIFY_WITNESS
        solution_script = tx_context.solution_script
        puzzle_script = tx_context.puzzle_script

        had_witness = False

        is_p2h = class_.is_pay_to_script_hash(puzzle_script)

        if flags & VERIFY_SIGPUSHONLY:
            class_.VM.ScriptCodec.check_script_push_only(solution_script)

        vm_context = VMContext()
        # never use VERIFY_MINIMALIF or VERIFY_WITNESS_PUBKEYTYPE except in segwit
        vm_context.flags = flags & ~(VERIFY_MINIMALIF | VERIFY_WITNESS_PUBKEYTYPE)
        vm_context.is_solution_script = True
        vm_context.signature_for_hash_type_f = tx_context.signature_for_hash_type_f
        vm_context.traceback_f = traceback_f

        vm = class_.VM()
        stack = vm.eval_script(solution_script, tx_context, vm_context)

        if is_p2h and (flags & VERIFY_P2SH):
            p2sh_solution_blob, p2sh_puzzle_script = stack[:-1], stack[-1]
            p2sh_solution_script = class_.VM.bin_script(p2sh_solution_blob)

        stack = vm.eval_script(puzzle_script, tx_context, vm_context, initial_stack=stack)

        if len(stack) == 0 or not class_.VM.bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)

        if flags & VERIFY_WITNESS:
            had_witness = class_.check_witness(tx_context, flags, traceback_f)

        if is_p2h and class_.VM.bool_from_script_bytes(stack[-1]) and (flags & VERIFY_P2SH):
            class_.VM.ScriptCodec.check_script_push_only(solution_script)
            vm_context.is_psh_script = True
            p2sh_flags = flags & ~VERIFY_P2SH
            p2sh_tx_context = TxContext()
            p2sh_tx_context.puzzle_script = p2sh_puzzle_script
            p2sh_tx_context.solution_script = p2sh_solution_script
            p2sh_tx_context.witness_solution_stack = tx_context.witness_solution_stack
            p2sh_tx_context.signature_for_hash_type_f = tx_context.signature_for_hash_type_f
            p2sh_tx_context.sequence = tx_context.sequence
            p2sh_tx_context.version = tx_context.version
            p2sh_tx_context.lock_time = tx_context.lock_time
            class_.check_solution(p2sh_tx_context, p2sh_flags)
            return

        if (flags & VERIFY_WITNESS) and not had_witness and len(tx_context.witness_solution_stack) > 0:
            raise ScriptError("witness unexpected", errno.WITNESS_UNEXPECTED)

        if flags & VERIFY_CLEANSTACK and len(stack) != 1:
            raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

        if len(stack) == 0 or not class_.VM.bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)
