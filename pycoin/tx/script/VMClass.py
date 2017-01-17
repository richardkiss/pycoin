
from .flags import (
    VERIFY_P2SH, VERIFY_SIGPUSHONLY, VERIFY_CLEANSTACK,
    VERIFY_WITNESS, VERIFY_MINIMALIF, VERIFY_WITNESS_PUBKEYTYPE
)

from .tools import bin_script, bool_from_script_bytes, get_opcode
from . import ScriptError
from . import errno
from . import opcodes


SCRIPT_TYPE_SOLUTION = 1
SCRIPT_TYPE_PUZZLE = 2
SCRIPT_TYPE_P2H_SOLUTION = 3
SCRIPT_TYPE_P2H_PUZZLE = 4
SCRIPT_TYPE_WITNESS_SOLUTION = 5
SCRIPT_TYPE_WITNESS_PUZZLE = 6


class VMState(object):
    def __init__(self):
        pass


class VM(object):
    def __init__(self):
        pass

    def get_opcode(self, script, pc):
        return get_opcode(script, pc)

    def check_script_push_only(self, script):
        pc = 0
        while pc < len(script):
            opcode, data, pc = self.get_opcode(script, pc)
            if opcode > opcodes.OP_16:
                raise ScriptError("signature has non-push opcodes", errno.SIG_PUSHONLY)

    def check(self, vm_state=None, **kwargs):
        if vm_state is None:
            vm_state = VMState(**kwargs)
        elif len(kwargs) > 0:
            raise ValueError("if vm_state set, no other args allowed")
        self._check(vm_state)

    def _check(self, vm_state, tx_context):
        flags = vm_state.flags
        stack = vm_state.stack

        had_witness = False

        is_p2h = self.is_pay_to_script_hash(vm_state.puzzle_script)

        if flags & VERIFY_SIGPUSHONLY:
            self.check_script_push_only(vm_state.puzzle_script)

        # never use VERIFY_MINIMALIF or VERIFY_WITNESS_PUBKEYTYPE except in segwit
        original_flags = flags
        vm_state.flags &= ~(VERIFY_MINIMALIF | VERIFY_WITNESS_PUBKEYTYPE)

        vm_state.is_solution_script = True
        self.eval_script(vm_state, tx_context)

        if is_p2h and (flags & VERIFY_P2SH):
            signatures, p2sh_puzzle_script = stack[:-1], stack[-1]
            p2sh_solution_script = bin_script(signatures)

        vm_state.is_puzzle_script = True
        self.eval_script(vm_state, tx_context)

        if len(stack) == 0 or not bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)

        if flags & VERIFY_WITNESS:
            vm_state.flags = original_flags
            had_witness = self.check_witness(vm_state, tx_context)

        if is_p2h and bool_from_script_bytes(stack[-1]) and (flags & VERIFY_P2SH):
            vm_state.is_psh_script = True
            vm_state.flags &= VERIFY_P2SH
            vm_state.flags |= VERIFY_SIGPUSHONLY
            vm_state.solution_script = p2sh_solution_script
            vm_state.puzzle_script = p2sh_puzzle_script
            self.check_script(vm_state, tx_context)
            return

        if (flags & VERIFY_WITNESS) and not had_witness and len(vm_state.witness) > 0:
            raise ScriptError("witness unexpected", errno.WITNESS_UNEXPECTED)

        if flags & VERIFY_CLEANSTACK and len(stack) != 1:
            raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

        if len(stack) == 0 or not bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)
