import binascii
import functools
import io
import struct

from .flags import VERIFY_MINIMALDATA

from ...intbytes import byte_to_int, bytes_from_int, bytes_to_ints, int_to_bytes, from_bytes

from .ints import int_from_script_bytes, int_to_script_bytes
from . import ScriptError
from . import errno
from . import opcodes
from .instruction_lookup import make_instruction_lookup


def compile_expression(t):
    if (t[0], t[-1]) == ('[', ']'):
        return binascii.unhexlify(t[1:-1])
    if t.startswith("'") and t.endswith("'"):
        return t[1:-1].encode("utf8")
    try:
        t0 = int(t)
        if abs(t0) <= 18446744073709551615 and t[0] != '0':
            return int_to_script_bytes(t0)
    except (SyntaxError, ValueError):
        pass
    try:
        return binascii.unhexlify(t)
    except Exception:
        pass
    raise SyntaxError("unknown expression %s" % t)


class VM(object):
    MAX_SCRIPT_LENGTH = 10000
    MAX_BLOB_LENGTH = 520
    MAX_OP_COUNT = 201
    MAX_STACK_SIZE = 1000
    OPCODE_LIST = opcodes.OPCODE_LIST

    @classmethod
    def build_microcode(class_):
        class_.INSTRUCTION_LOOKUP = make_instruction_lookup(class_.OPCODE_LIST)
        class_.OPCODE_TO_INT = dict(o for o in class_.OPCODE_LIST)
        class_.INT_TO_OPCODE = dict(reversed(i) for i in class_.OPCODE_LIST)

    @classmethod
    def check_script_push_only(class_, script):
        pc = 0
        while pc < len(script):
            opcode, data, pc = class_.get_opcode(script, pc)
            if opcode > opcodes.OP_16:
                raise ScriptError("signature has non-push opcodes", errno.SIG_PUSHONLY)

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

    @classmethod
    def get_opcode(class_, script, pc):
        """
        Step through the script, returning a tuple with the next opcode, the next
        piece of data (if the opcode represents data), and the new PC.
        """
        opcode = ord(script[pc:pc+1])
        pc += 1
        data = None
        if opcode <= class_.OPCODE_TO_INT["OP_PUSHDATA4"]:
            if opcode < class_.OPCODE_TO_INT["OP_PUSHDATA1"]:
                size = opcode
            elif opcode == class_.OPCODE_TO_INT["OP_PUSHDATA1"]:
                size = from_bytes(script[pc:pc+1], byteorder="little")
                pc += 1
            elif opcode == class_.OPCODE_TO_INT["OP_PUSHDATA2"]:
                size = from_bytes(script[pc:pc+2], byteorder="little")
                pc += 2
            elif opcode == class_.OPCODE_TO_INT["OP_PUSHDATA4"]:
                size = from_bytes(script[pc:pc+4], byteorder="little")
                pc += 4
            data = script[pc:pc+size]
            if len(data) < size:
                raise ScriptError("unexpected end of data when literal expected", errno.BAD_OPCODE)
            pc += size
        return opcode, data, pc

    @classmethod
    def write_push_data(class_, data_list, f):
        # return bytes that causes the given data to be pushed onto the stack
        for t in data_list:
            if len(t) == 0:
                f.write(bytes_from_int(class_.OPCODE_TO_INT["OP_0"]))
                continue
            if len(t) == 1:
                v = bytes_to_ints(t)[0]
                if v <= 16:
                    f.write(bytes_from_int(class_.OPCODE_TO_INT["OP_%d" % v]))
                    continue
            if len(t) <= 255:
                if len(t) > 75:
                    f.write(bytes_from_int(class_.OPCODE_TO_INT["OP_PUSHDATA1"]))
                f.write(int_to_bytes(len(t)))
                f.write(t)
            elif len(t) <= 65535:
                f.write(bytes_from_int(class_.OPCODE_TO_INT["OP_PUSHDATA2"]))
                f.write(struct.pack("<H", len(t)))
                f.write(t)
            else:
                # This will never be used in practice as it makes the scripts too long.
                f.write(bytes_from_int(class_.OPCODE_TO_INT["OP_PUSHDATA4"]))
                f.write(struct.pack("<L", len(t)))
                f.write(t)

    @classmethod
    def bin_script(class_, data_list):
        f = io.BytesIO()
        class_.write_push_data(data_list, f)
        return f.getvalue()

    @classmethod
    def compile(class_, s):
        """
        Compile the given script. Returns a bytes object with the compiled script.
        """
        f = io.BytesIO()
        for t in s.split():
            if t in class_.OPCODE_TO_INT:
                f.write(bytes_from_int(class_.OPCODE_TO_INT[t]))
            elif ("OP_%s" % t) in class_.OPCODE_TO_INT:
                f.write(bytes_from_int(class_.OPCODE_TO_INT["OP_%s" % t]))
            elif t.startswith("0x"):
                d = binascii.unhexlify(t[2:])
                f.write(d)
            else:
                v = compile_expression(t)
                class_.write_push_data([v], f)
        return f.getvalue()

    @classmethod
    def disassemble_for_opcode_data(class_, opcode, data):
        if data is not None and len(data) > 0:
            return "[%s]" % binascii.hexlify(data).decode("utf8")
        return class_.INT_TO_OPCODE.get(opcode, "???")

    @classmethod
    def opcode_list(class_, script):
        """Disassemble the given script. Returns a list of opcodes."""
        opcodes = []
        pc = 0
        while pc < len(script):
            try:
                opcode, data, pc = class_.get_opcode(script, pc)
            except ScriptError:
                opcodes.append(binascii.hexlify(script[pc:]).decode("utf8"))
                break
            opcodes.append(class_.disassemble_for_opcode_data(opcode, data))
        return opcodes

    @classmethod
    def disassemble(class_, script):
        """Disassemble the given script. Returns a string."""
        return ' '.join(class_.opcode_list(script))

    @classmethod
    def delete_subscript(class_, script, subscript):
        """
        Returns a script with the given subscript removed. The subscript
        must appear in the main script aligned to opcode boundaries for it
        to be removed.
        """
        new_script = bytearray()
        pc = 0
        while pc < len(script):
            opcode, data, new_pc = class_.get_opcode(script, pc)
            section = script[pc:new_pc]
            if section != subscript:
                new_script.extend(section)
            pc = new_pc
        return bytes(new_script)

    def eval_script(self, script, tx_context, vm_context, initial_stack=None):
        from pycoin.tx.script.Stack import Stack

        if len(script) > self.MAX_SCRIPT_LENGTH:
            raise ScriptError("script too long", errno.SCRIPT_SIZE)

        self.pc = 0
        self.tx_context = tx_context
        self.stack = initial_stack or Stack()
        self.script = script
        self.altstack = Stack()
        self.if_condition_stack = []
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
        opcode, data, pc = self.get_opcode(self.script, self.pc)
        if data and len(data) > self.MAX_BLOB_LENGTH:
            raise ScriptError("pushing too much data onto stack", errno.PUSH_SIZE)
        if opcode > opcodes.OP_16:
            self.op_count += 1

        self.check_stack_size()

        if self.traceback_f:
            self.traceback_f(opcode, data, pc, self)

        all_if_true = functools.reduce(lambda x, y: x and y, self.if_condition_stack, True)
        if data is not None and all_if_true:
            if self.flags & VERIFY_MINIMALDATA:
                self.verify_minimal_data(opcode, data)
            self.stack.append(data)

        f = self.INSTRUCTION_LOOKUP[opcode]
        if getattr(f, "outside_conditional", False) or all_if_true:
            f(self)

        self.pc = pc

        if self.op_count > self.MAX_OP_COUNT:
            raise ScriptError("script contains too many operations", errno.OP_COUNT)

    def check_stack_size(self):
        if len(self.stack) + len(self.altstack) > self.MAX_STACK_SIZE:
            raise ScriptError("stack has > %d items" % self.MAX_STACK_SIZE, errno.STACK_SIZE)

    def post_script_check(self):
        if len(self.if_condition_stack):
            raise ScriptError("missing ENDIF", errno.UNBALANCED_CONDITIONAL)

        self.check_stack_size()


# BRAIN DAMAGE
VM.build_microcode()
