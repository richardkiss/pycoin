
from .flags import (
    VERIFY_P2SH,
    VERIFY_SIGPUSHONLY, VERIFY_CLEANSTACK,
    VERIFY_WITNESS, VERIFY_MINIMALIF, VERIFY_WITNESS_PUBKEYTYPE
)

from .BaseVM import VM

from . import ScriptError
from . import errno


class TxContext(object):
    pass


class VMContext(object):
    pass


class SolutionChecker(object):
    VM = VM

    @classmethod
    def is_pay_to_script_hash(class_, script_public_key):
        raise NotImplemented()

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

        if flags & VERIFY_SIGPUSHONLY:
            class_.VM.ScriptCodec.check_script_push_only(solution_script)

        vm_context = VMContext()
        # never use VERIFY_MINIMALIF or VERIFY_WITNESS_PUBKEYTYPE except in segwit
        vm_context.flags = flags & ~(VERIFY_MINIMALIF | VERIFY_WITNESS_PUBKEYTYPE)
        vm_context.is_solution_script = True
        vm_context.signature_for_hash_type_f = tx_context.signature_for_hash_type_f
        vm_context.traceback_f = traceback_f

        vm = class_.VM()
        solution_stack = vm.eval_script(solution_script, tx_context, vm_context)

        # work on a copy of the solution stack
        stack = vm.eval_script(puzzle_script, tx_context, vm_context, initial_stack=solution_stack[:])

        if len(stack) == 0 or not class_.VM.bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)

        had_witness = False
        if flags & VERIFY_WITNESS:
            had_witness = class_.check_witness(tx_context, flags, traceback_f)

        if class_.is_pay_to_script_hash(puzzle_script) and (flags & VERIFY_P2SH):
            p2sh_solution_blob, p2sh_puzzle_script = solution_stack[:-1], solution_stack[-1]
            p2sh_solution_script = class_.VM.bin_script(p2sh_solution_blob)
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

        if flags & VERIFY_CLEANSTACK and len(stack) != 1:
            raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

        if (flags & VERIFY_WITNESS) and not had_witness and len(tx_context.witness_solution_stack) > 0:
            raise ScriptError("witness unexpected", errno.WITNESS_UNEXPECTED)
