from .flags import VERIFY_MINIMALDATA

from . import ScriptError
from . import errno
from . import opcodes
from .ConditionalStack import ConditionalStack
from .IntStreamer import IntStreamer


class VM(object):
    MAX_SCRIPT_LENGTH = 10000
    MAX_BLOB_LENGTH = 520
    MAX_OP_COUNT = 201
    MAX_STACK_SIZE = 1000
    OPCODE_LIST = opcodes.OPCODE_LIST

    VM_FALSE = IntStreamer.int_to_script_bytes(0)
    VM_TRUE = IntStreamer.int_to_script_bytes(1)

    ConditionalStack = ConditionalStack
    IntStreamer = IntStreamer

    @classmethod
    def nonnegative_int_from_script_bytes(class_, b, require_minimal):
        v = class_.IntStreamer.int_from_script_bytes(b, require_minimal=require_minimal)
        if v < 0:
            raise ScriptError("unexpectedly got negative value", errno.INVALID_STACK_OPERATION)
        return v

    @classmethod
    def bool_from_script_bytes(class_, v, require_minimal=False):
        v = class_.IntStreamer.int_from_script_bytes(v, require_minimal=require_minimal)
        if require_minimal:
            if v not in (0, 1):
                raise ScriptError("non-minimally encoded", errno.UNKNOWN_ERROR)
        return bool(v)

    @classmethod
    def bool_to_script_bytes(class_, v):
        return class_.VM_TRUE if v else class_.VM_FALSE

    @classmethod
    def get_opcodes(class_, script, verify_minimal_data=False, pc=0):
        pc = 0
        while pc < len(script):
            opcode, data, new_pc = class_.ScriptCodec.get_opcode(script, pc, verify_minimal_data=verify_minimal_data)
            yield opcode, data, pc, new_pc
            pc = new_pc

    def eval_script(self, script, tx_context, vm_context, initial_stack=None):
        if len(script) > self.MAX_SCRIPT_LENGTH:
            raise ScriptError("script too long", errno.SCRIPT_SIZE)

        self.pc = 0
        self.tx_context = tx_context
        self.stack = initial_stack or list()
        self.script = script
        self.altstack = list()
        self.conditional_stack = self.ConditionalStack()
        self.op_count = 0
        self.begin_code_hash = 0
        self.flags = vm_context.flags
        self.traceback_f = vm_context.traceback_f
        self.signature_for_hash_type_f = vm_context.signature_for_hash_type_f

        while self.pc < len(self.script):
            self.eval_instruction()

        self.post_script_check()
        return self.stack

    def eval_instruction(self):
        all_if_true = self.conditional_stack.all_if_true()

        # don't actually check for minimal data unless data will be pushed onto the stack
        verify_minimal_data = self.flags & VERIFY_MINIMALDATA and all_if_true
        opcode, data, pc = self.ScriptCodec.get_opcode(self.script, self.pc, verify_minimal_data=verify_minimal_data)
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

    @classmethod
    def delete_subscript(class_, script, subscript):
        """
        Returns a script with the given subscript removed. The subscript
        must appear in the main script aligned to opcode boundaries for it
        to be removed.
        """
        new_script = bytearray()
        pc = 0
        for opcode, data, pc, new_pc in class_.get_opcodes(script):
            section = script[pc:new_pc]
            if section != subscript:
                new_script.extend(section)
        return bytes(new_script)
