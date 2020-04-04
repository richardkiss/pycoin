import binascii
import io

from ..intbytes import int2byte

from pycoin.coins.SolutionChecker import ScriptError


class ScriptTools(object):

    def __init__(self, opcode_list, IntStreamer, scriptStreamer):
        self.intStreamer = IntStreamer
        self.scriptStreamer = scriptStreamer

        self.opcode_to_int = dict(o for o in opcode_list)
        self.int_to_opcode = dict(reversed(o) for o in opcode_list)

    def int_for_opcode(self, opcode):
        return self.opcode_to_int.get(opcode)

    def compile_expression(self, t):
        if (t[0], t[-1]) == ('[', ']'):
            return binascii.unhexlify(t[1:-1])
        if t.startswith("'") and t.endswith("'"):
            return t[1:-1].encode("utf8")
        try:
            t0 = int(t)
            if abs(t0) <= 0xffffffffffffffff and t[0] != '0':
                return self.intStreamer.int_to_script_bytes(t0)
        except (SyntaxError, ValueError):
            pass
        try:
            return binascii.unhexlify(t)
        except Exception:
            pass
        raise SyntaxError("unknown expression %s" % t)

    def compile(self, s):
        """
        Compile the given script. Returns a bytes object with the compiled script.
        """
        f = io.BytesIO()
        for t in s.split():
            t_up = t.upper()
            if t_up in self.opcode_to_int:
                f.write(int2byte(self.opcode_to_int[t]))
            elif ("OP_%s" % t_up) in self.opcode_to_int:
                f.write(int2byte(self.opcode_to_int["OP_%s" % t]))
            elif t_up.startswith("0X"):
                d = binascii.unhexlify(t[2:])
                f.write(d)
            else:
                v = self.compile_expression(t)
                self.write_push_data([v], f)
        return f.getvalue()

    def disassemble_for_opcode_data(self, opcode, data):
        # TODO: check data for int or string representation
        opcode_str = self.int_to_opcode.get(opcode, "???")
        if data is not None and len(data) > 0 and opcode_str.startswith("OP_PUSH"):
            return "[%s]" % binascii.hexlify(data).decode("utf8")
        return opcode_str

    def get_opcodes(self, script, verify_minimal_data=False, pc=0):
        """
        Iterator. Return opcode, data, pc, new_pc at each step
        """
        while pc < len(script):
            opcode, data, new_pc, is_ok = self.scriptStreamer.get_opcode(
                script, pc, verify_minimal_data=verify_minimal_data)
            yield opcode, data, pc, new_pc
            pc = new_pc

    def opcode_list(self, script):
        """Disassemble the given script. Returns a list of opcodes."""
        opcodes = []
        new_pc = 0
        try:
            for opcode, data, pc, new_pc in self.get_opcodes(script):
                opcodes.append(self.disassemble_for_opcode_data(opcode, data))
        except ScriptError:
            opcodes.append(binascii.hexlify(script[new_pc:]).decode("utf8"))

        return opcodes

    def disassemble(self, script):
        """Disassemble the given script. Returns a string."""
        return ' '.join(self.opcode_list(script))

    def write_push_data(self, data_list, f):
        # return bytes that causes the given data to be pushed onto the stack
        for t in data_list:
            f.write(self.scriptStreamer.compile_push_data(t))

    def compile_push_data_list(self, data_list):
        return b''.join(self.scriptStreamer.compile_push_data(d) for d in data_list if d is not None)
