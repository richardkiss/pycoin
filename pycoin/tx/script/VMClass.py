import functools

from hashlib import sha256

from .flags import (
    VERIFY_P2SH, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_SIGPUSHONLY, VERIFY_CLEANSTACK,
    VERIFY_WITNESS, VERIFY_MINIMALIF, VERIFY_WITNESS_PUBKEYTYPE, VERIFY_MINIMALDATA,
)

from ...intbytes import byte_to_int

from .tools import bin_script, bool_from_script_bytes, get_opcode
from .tools import int_from_script_bytes
from . import ScriptError
from . import errno
from . import opcodes
from .eval_script import make_instruction_lookup

from .Stack import Stack


class TxContext(object):
    pass


class TxInContext(object):
    pass


class VMState(object):
    pass


class VMContext(object):
    pass


class SolutionChecker(object):
    def __init__(self):
        pass

    @staticmethod
    def is_pay_to_script_hash(script_public_key):
        return (len(script_public_key) == 23 and byte_to_int(script_public_key[0]) == opcodes.OP_HASH160 and
                byte_to_int(script_public_key[-1]) == opcodes.OP_EQUAL)

    @staticmethod
    def get_opcode(script, pc):
        return get_opcode(script, pc)

    def check_script_push_only(self, script):
        pc = 0
        while pc < len(script):
            opcode, data, pc = self.get_opcode(script, pc)
            if opcode > opcodes.OP_16:
                raise ScriptError("signature has non-push opcodes", errno.SIG_PUSHONLY)

    def check_witness_program_v0(self, witness_solution_stack, witness_program, tx_context, flags):
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
            # "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG" % b2h(script_signature))
            puzzle_script = b'v\xa9' + bin_script([witness_program]) + b'\x88\xac'
            stack = Stack(witness_solution_stack)
        else:
            raise ScriptError("witness program wrong length", errno.WITNESS_PROGRAM_WRONG_LENGTH)
        return stack, puzzle_script

    def check_witness_program(
            self, version, witness_solution_stack, witness_program, flags, tx_context):
        if version == 0:
            stack, witness_puzzle_script = self.check_witness_program_v0(
                witness_solution_stack, witness_program, flags, tx_context)
        elif flags & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
            raise ScriptError(
                "this version witness program not yet supported", errno.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        else:
            return

        for s in stack:
            if len(s) > 520:
                raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)

        vm = VM()
        vm_context = VMContext()
        vm_context.flags = flags
        vm.eval_script(witness_puzzle_script, tx_context, vm_context, initial_stack=stack)

        if len(stack) == 0 or not bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)

        if len(stack) != 1:
            raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

    @staticmethod
    def witness_program_version(script):
        l = len(script)
        if l < 4 or l > 42:
            return None
        first_opcode = byte_to_int(script[0])
        if byte_to_int(script[1]) + 2 != l:
            return None
        if first_opcode == opcodes.OP_0:
            return 0
        if opcodes.OP_1 <= first_opcode <= opcodes.OP_16:
            return first_opcode - opcodes.OP_1 + 1
        return None

    def check_witness(self, tx_in_context, tx_context, vm_context, flags):
        witness_version = self.witness_program_version(tx_in_context.puzzle_script)
        had_witness = False
        if witness_version is not None:
            had_witness = True
            witness_puzzle = tx_in_context.puzzle_script[2:]
            if len(tx_in_context.solution_script) > 0:
                err = errno.WITNESS_MALLEATED if flags & VERIFY_P2SH else errno.WITNESS_MALLEATED_P2SH
                raise ScriptError("script sig is not blank on segwit input", err)
            self.check_witness_program(
                witness_version, tx_in_context.witness_solution_stack, witness_puzzle, flags, tx_context)
        return had_witness

    def _check_solution(self, tx_in_context, tx_context, flags):
        """
        solution_script: alleged solution to the puzzle_script
        puzzle_script: the script protecting the coins
        tx_context: information about the transaction that the VM may need
        flags: gives the VM hints about which additional constraints to check
        """

        solution_script = tx_in_context.solution_script
        puzzle_script = tx_in_context.puzzle_script

        had_witness = False

        is_p2h = self.is_pay_to_script_hash(puzzle_script)

        if flags & VERIFY_SIGPUSHONLY:
            self.check_script_push_only(solution_script)

        vm_context = VMContext()
        # never use VERIFY_MINIMALIF or VERIFY_WITNESS_PUBKEYTYPE except in segwit
        vm_context.flags = flags & ~(VERIFY_MINIMALIF | VERIFY_WITNESS_PUBKEYTYPE)
        vm_context.is_solution_script = True

        vm = VM()
        stack = vm.eval_script(solution_script, tx_context, vm_context)

        if is_p2h and (flags & VERIFY_P2SH):
            p2sh_solution_blob, p2sh_puzzle_script = stack[:-1], stack[-1]
            p2sh_solution_script = bin_script(p2sh_solution_blob)

        stack = vm.eval_script(puzzle_script, tx_context, vm_context, initial_stack=stack)

        if len(stack) == 0 or not bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)

        if flags & VERIFY_WITNESS:
            had_witness = self.check_witness(tx_in_context, tx_context, vm_context, flags)

        if is_p2h and bool_from_script_bytes(stack[-1]) and (flags & VERIFY_P2SH):
            self.check_script_push_only(solution_script)
            vm_context.is_psh_script = True
            flags = vm_context.flags
            flags &= ~VERIFY_P2SH
            p2sh_tx_in_context = TxInContext()
            p2sh_tx_in_context.puzzle_script = p2sh_puzzle_script
            p2sh_tx_in_context.solution_script = p2sh_solution_script
            p2sh_tx_in_context.witness_solution_stack = tx_in_context.witness_solution_stack
            self._check_solution(p2sh_tx_in_context, tx_context, flags)
            return

        if (flags & VERIFY_WITNESS) and not had_witness and len(tx_in_context.witness_solution_stack) > 0:
            raise ScriptError("witness unexpected", errno.WITNESS_UNEXPECTED)

        if flags & VERIFY_CLEANSTACK and len(stack) != 1:
            raise ScriptError("stack not clean after evaluation", errno.CLEANSTACK)

        if len(stack) == 0 or not bool_from_script_bytes(stack[-1]):
            raise ScriptError("eval false", errno.EVAL_FALSE)


class VM(object):
    MAX_SCRIPT_LENGTH = 10000
    MAX_BLOB_LENGTH = 520
    MAX_OP_COUNT = 201
    MAX_STACK_SIZE = 1000
    MICROCODE = make_instruction_lookup()

    @staticmethod
    def verify_minimal_data(opcode, data):
        ld = len(data)
        if ld == 0 and opcode == opcodes.OP_0:
            return
        if ld == 1:
            v = byte_to_int(data[0])
            if v == 0x81:
                if opcode == opcodes.OP_1NEGATE:
                    return
            elif v == 0 or v > 16:
                return
            elif v == (opcode - 1 + opcodes.OP_1):
                return
        if 1 < ld < 0x4c and opcode == ld:
            return
        if 0x4c <= ld < 256 and opcode == opcodes.OP_PUSHDATA1:
            return
        if 256 < ld < 65536 and opcode == opcodes.OP_PUSHDATA2:
            return
        raise ScriptError("not minimal push of %s" % repr(data), errno.MINIMALDATA)

    def eval_script(self, script, tx_context, vm_context, initial_stack=None):
        from pycoin.tx.script.Stack import Stack

        if len(script) > self.MAX_SCRIPT_LENGTH:
            raise ScriptError("script too long", errno.SCRIPT_SIZE)

        self.pc = 0
        self.tx_context = tx_context
        self.stack = initial_stack or Stack()
        self.script = script
        self.signature_for_hash_type_f = tx_context.signature_for_hash_type_f
        self.lock_time = tx_context.lock_time
        self.altstack = Stack()
        self.if_condition_stack = []
        self.op_count = 0
        self.flags = vm_context.flags
        self.begin_code_hash = 0

        while self.pc < len(self.script):
            opcode, data, pc = get_opcode(self.script, self.pc)

            # if traceback_f:
            #    traceback_f(old_pc, opcode, data, stack, altstack, if_condition_stack, is_signature)

            if data and len(data) > self.MAX_BLOB_LENGTH:
                raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)
            if opcode > opcodes.OP_16:
                self.op_count += 1
            stack_top = self.stack[-1] if self.stack else b''

            self.check_stack_size()
            self.eval_instruction()

            if opcode in (opcodes.OP_CHECKMULTISIG, opcodes.OP_CHECKMULTISIGVERIFY):
                self.op_count += int_from_script_bytes(stack_top)
            if self.op_count > self.MAX_OP_COUNT:
                raise ScriptError("script contains too many operations", errno.OP_COUNT)

        self.post_script_check()
        return self.stack

    def eval_instruction(self):  # ss, pc, microcode=DEFAULT_MICROCODE):
        opcode, data, new_pc = get_opcode(self.script, self.pc)

        all_if_true = functools.reduce(lambda x, y: x and y, self.if_condition_stack, True)
        if data is not None and all_if_true:
            if self.flags & VERIFY_MINIMALDATA:
                self.verify_minimal_data(opcode, data)
            self.stack.append(data)

        f = self.MICROCODE.get(opcode, lambda *args, **kwargs: 0)
        if getattr(f, "outside_conditional", False) or all_if_true:
            f(self)

        self.pc = new_pc

    def check_stack_size(self):
        if len(self.stack) + len(self.altstack) > self.MAX_STACK_SIZE:
            raise ScriptError("stack has > %d items" % self.MAX_STACK_SIZE, errno.STACK_SIZE)

    def post_script_check(self):
        if len(self.if_condition_stack):
            raise ScriptError("missing ENDIF", errno.UNBALANCED_CONDITIONAL)

        self.check_stack_size()

