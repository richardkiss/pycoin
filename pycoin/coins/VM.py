
from ..ecdsa.secp256k1 import secp256k1_generator
from ..tx.script import errno
from ..tx.script.flags import VERIFY_MINIMALDATA
from ..tx.script.ConditionalStack import ConditionalStack
from ..tx.script.IntStreamer import IntStreamer

from .SolutionChecker import ScriptError


class VMContext(object):
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
        self.conditional_stack = self.ConditionalStack()
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
    # BRAIN DAMAGE
    def generator_for_signature_type(class_, signature_type):
        return secp256k1_generator


class VM(object):
    @classmethod
    def eval_script(class_, vmc):
        if len(vmc.script) > vmc.MAX_SCRIPT_LENGTH:
            raise ScriptError("script too long", errno.SCRIPT_SIZE)

        f = getattr(vmc.traceback_f, "prelaunch", None)
        if f:
            f(vmc)

        while vmc.pc < len(vmc.script):
            class_.eval_instruction(vmc)

        f = getattr(vmc.traceback_f, "postscript", None)
        if f:
            f(vmc)

        class_.post_script_check(vmc)
        return vmc.stack

    @classmethod
    def eval_instruction(class_, vmc):
        all_if_true = vmc.conditional_stack.all_if_true()

        # don't actually check for minimal data unless data will be pushed onto the stack
        verify_minimal_data = vmc.flags & VERIFY_MINIMALDATA and all_if_true
        opcode, data, pc = class_.ScriptStreamer.get_opcode(
            vmc.script, vmc.pc, verify_minimal_data=verify_minimal_data)
        if data and len(data) > vmc.MAX_BLOB_LENGTH:
            raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)

        if data is None:
            vmc.op_count += 1

        class_.check_stack_size(vmc)

        f = class_.INSTRUCTION_LOOKUP[opcode]
        if vmc.traceback_f:
            f = vmc.traceback_f(opcode, data, pc, vmc) or f

        if data is not None and all_if_true:
            vmc.stack.append(data)

        if all_if_true or getattr(f, "outside_conditional", False):
            f(vmc)

        vmc.pc = pc

        if vmc.op_count > vmc.MAX_OP_COUNT:
            raise ScriptError("script contains too many operations", errno.OP_COUNT)

    @classmethod
    def check_stack_size(class_, vmc):
        if len(vmc.stack) + len(vmc.altstack) > vmc.MAX_STACK_SIZE:
            raise ScriptError("stack has > %d items" % vmc.MAX_STACK_SIZE, errno.STACK_SIZE)

    @classmethod
    def post_script_check(class_, vmc):
        vmc.conditional_stack.check_final_state()
        class_.check_stack_size(vmc)

    @classmethod
    def generator_for_signature_type(class_, signature_type):
        return secp256k1_generator
