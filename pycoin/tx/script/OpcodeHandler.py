import binascii
import io
import struct

from ...intbytes import byte_to_int, bytes_from_int, int_to_bytes, from_bytes

from . import ScriptError
from . import errno
from . import opcodes


class ScriptStreamer(object):
    def __init__(self, opcode_pair_list):
        self.opcode_to_int = dict(o for o in opcode_pair_list)
        self.int_to_opcode = dict(reversed(i) for i in opcode_pair_list)
        for k, v in opcode_pair_list:
            setattr(self, k, v)

    def check_script_push_only(self, script):
        pc = 0
        while pc < len(script):
            opcode, data, pc = self.get_opcode(script, pc)
            if opcode > opcodes.OP_16:
                raise ScriptError("signature has non-push opcodes", errno.SIG_PUSHONLY)

    def verify_minimal_data(self, opcode, data):
        script = self.bin_script([data])
        if byte_to_int(script[0]) != opcode:
            raise ScriptError("not minimal push of %s" % repr(data), errno.MINIMALDATA)

    def get_opcode(self, script, pc):
        """
        Step through the script, returning a tuple with the next opcode, the next
        piece of data (if the opcode represents data), and the new PC.
        """
        opcode = byte_to_int(script[pc])
        f = self.INSTRUCTION_DECODE_LOOKUP.get(opcode)
        if f:
            pc, data = f(script, pc)
        else:
            pc += 1
            data = None
        return opcode, data, pc

    def compile_push(self, data):
        # return bytes that causes the given data to be pushed onto the stack
        if len(data) == 0:
            return bytes_from_int(self.OP_0)
        if len(data) == 1:
            v = self.int_from_script_bytes(data)
            if v == -1:
                v = "1NEGATE"
            opcode_str = "OP_%s" % v
            opcode = self.OPCODE_TO_INT.get(opcode_str)
            if opcode:
                return bytes_from_int(opcode)
        if len(data) <= 255:
            prefix = b''
            if len(data) > 75:
                prefix = bytes_from_int(self.OP_PUSHDATA1)
            return prefix + int_to_bytes(len(data)) + data
        if len(data) <= 65535:
            return bytes_from_int(self.OP_PUSHDATA2) + struct.pack("<H", len(data)) + data

        # This will never be used in practice as it makes the scripts too long.
        return bytes_from_int(self.OP_PUSHDATA4) + struct.pack("<L", len(data)) + data

    def write_push_data(self, data_list, f):
        # return bytes that causes the given data to be pushed onto the stack
        for t in data_list:
            f.write(self.compile_push(t))

    def bin_script(self, data_list):
        f = io.BytesIO()
        self.write_push_data(data_list, f)
        return f.getvalue()

    def compile(self, s):
        """
        Compile the given script. Returns a bytes object with the compiled script.
        """
        f = io.BytesIO()
        for t in s.split():
            if t in self.OPCODE_TO_INT:
                f.write(bytes_from_int(self.OPCODE_TO_INT[t]))
            elif ("OP_%s" % t) in self.OPCODE_TO_INT:
                f.write(bytes_from_int(self.OPCODE_TO_INT["OP_%s" % t]))
            elif t.startswith("0x"):
                d = binascii.unhexlify(t[2:])
                f.write(d)
            else:
                v = self.compile_expression(t)
                f.write(self.compile_push(v))
        return f.getvalue()

    @classmethod
    def disassemble_for_opcode_data(self, opcode, data):
        if data is not None and len(data) > 0:
            return "[%s]" % binascii.hexlify(data).decode("utf8")
        return self.INT_TO_OPCODE.get(opcode, "???")

    @classmethod
    def opcode_list(self, script):
        """Disassemble the given script. Returns a list of opcodes."""
        opcodes = []
        pc = 0
        while pc < len(script):
            try:
                opcode, data, pc = self.get_opcode(script, pc)
            except ScriptError:
                opcodes.append(binascii.hexlify(script[pc:]).decode("utf8"))
                break
            opcodes.append(self.disassemble_for_opcode_data(opcode, data))
        return opcodes

    @classmethod
    def disassemble(self, script):
        """Disassemble the given script. Returns a string."""
        return ' '.join(self.opcode_list(script))


def make_instruction_decode_lookup(OPCODE_TO_INT):
    d = {}

    def make_decode_OP_declarator(dec_length):
        def decode_OP_PUSHDATA(script, pc):
            pc += 1
            size = from_bytes(script[pc:pc+dec_length], byteorder="little")
            pc += dec_length
            data = script[pc:pc+size]
            if len(data) < size:
                raise ScriptError("unexpected end of data when literal expected", errno.BAD_OPCODE)
            return pc+size, data
        return decode_OP_PUSHDATA

    def make_decode_OP_fixed_length(k):
        def decode(script, pc):
            pc += 1
            return pc+k, script[pc:pc+k]
        return decode

    for size in (1, 2, 4):
        d[OPCODE_TO_INT["OP_PUSHDATA%d" % size]] = make_decode_OP_declarator(size)

    # BRAIN DAMAGE: this is stupidly hardcoded
    for k in range(1, 76):
        d[k] = make_decode_OP_fixed_length(k)

    return d
