from pycoin.ecdsa.secp256k1 import secp256k1_generator  # BRAIN DAMAGE

from pycoin.satoshi import errno
from pycoin.satoshi.flags import VERIFY_MINIMALDATA
from pycoin.satoshi.IntStreamer import IntStreamer
from pycoin.vm.ConditionalStack import ConditionalStack

from pycoin.coins.SolutionChecker import ScriptError


def conditional_error_f(msg):
    raise ScriptError(msg, errno.UNBALANCED_CONDITIONAL)


class VM(object):
    MAX_SCRIPT_LENGTH = 10000
    MAX_BLOB_LENGTH = 520
    MAX_OP_COUNT = 201
    MAX_STACK_SIZE = 1000

    VM_FALSE = IntStreamer.int_to_script_bytes(0)
    VM_TRUE = IntStreamer.int_to_script_bytes(1)

    ConditionalStack = ConditionalStack
    IntStreamer = IntStreamer

    def __init__(self, script, tx_context, signature_for_hash_type_f, flags, initial_stack=None, traceback_f=None):
        self.pc = 0
        self.script = script
        self.tx_context = tx_context
        self.stack = initial_stack or list()
        self.altstack = list()
        self.conditional_stack = self.ConditionalStack(conditional_error_f)
        self.op_count = 0
        self.begin_code_hash = 0
        self.flags = flags
        self.traceback_f = traceback_f
        self.signature_for_hash_type_f = signature_for_hash_type_f

    def append(self, a):
        self.stack.append(a)

    def pop(self, *args, **kwargs):
        try:
            return self.stack.pop(*args, **kwargs)
        except IndexError:
            raise ScriptError("pop from empty stack", errno.INVALID_STACK_OPERATION)

    def __getitem__(self, *args, **kwargs):
        try:
            return self.stack.__getitem__(*args, **kwargs)
        except IndexError:
            raise ScriptError("getitem out of range", errno.INVALID_STACK_OPERATION)

    def pop_int(self):
        return self.IntStreamer.int_from_script_bytes(self.pop(), require_minimal=self.flags & VERIFY_MINIMALDATA)

    def pop_nonnegative(self):
        v = self.pop_int()
        if v < 0:
            raise ScriptError("unexpectedly got negative value", errno.INVALID_STACK_OPERATION)
        return v

    def push_int(self, v):
        self.append(self.IntStreamer.int_to_script_bytes(v))

    @classmethod
    def bool_from_script_bytes(class_, v, require_minimal=False):
        v = class_.IntStreamer.int_from_script_bytes(v, require_minimal=require_minimal)
        if require_minimal:
            if v not in (class_.VM_FALSE, class_.VM_TRUE):
                raise ScriptError("non-minimally encoded", errno.UNKNOWN_ERROR)
        return bool(v)

    @classmethod
    def bool_to_script_bytes(class_, v):
        return class_.VM_TRUE if v else class_.VM_FALSE

    @classmethod
    def generator_for_signature_type(class_, signature_type):
        return secp256k1_generator

    def eval_script(self):
        if len(self.script) > self.MAX_SCRIPT_LENGTH:
            raise ScriptError("script too long", errno.SCRIPT_SIZE)

        f = getattr(self.traceback_f, "prelaunch", None)
        if f:
            f(self)

        while self.pc < len(self.script):
            self.eval_instruction()

        f = getattr(self.traceback_f, "postscript", None)
        if f:
            f(self)

        self.post_script_check()
        return self.stack

    def eval_instruction(self):
        all_if_true = self.conditional_stack.all_if_true()

        # don't actually check for minimal data unless data will be pushed onto the stack
        verify_minimal_data = self.flags & VERIFY_MINIMALDATA and all_if_true
        opcode, data, pc = self.ScriptStreamer.get_opcode(
            self.script, self.pc, verify_minimal_data=verify_minimal_data)
        if data and len(data) > self.MAX_BLOB_LENGTH:
            raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)

        if data is None:
            self.op_count += 1

        self.check_stack_size()

        f = self.INSTRUCTION_LOOKUP[opcode]
        if self.traceback_f:
            f = self.traceback_f(opcode, data, pc, self) or f

        if data is not None and all_if_true:
            self.stack.append(data)

        if all_if_true or getattr(f, "outside_conditional", False):
            f(self)

        self.pc = pc

        if self.op_count > self.MAX_OP_COUNT:
            raise ScriptError("script contains too many operations", errno.OP_COUNT)

    def check_stack_size(self):
        if len(self.stack) + len(self.altstack) > self.MAX_STACK_SIZE:
            raise ScriptError("stack has > %d items" % self.MAX_STACK_SIZE, errno.STACK_SIZE)

    def post_script_check(self):
        self.conditional_stack.check_final_state()
        self.check_stack_size()
