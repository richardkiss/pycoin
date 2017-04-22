import binascii
import io

from ...intbytes import bytes_from_int

from . import ScriptError


class ScriptTools(object):

    def __init__(self, opcode_list, IntStreamer, dataCodec):
        self.intStreamer = IntStreamer
        self.dataCodec = dataCodec

        self.opcode_to_int = dict(o for o in opcode_list)
        self.int_to_opcode = dict(reversed(o) for o in opcode_list)
        # for k, v in self.OPCODE_LIST:
        #    setattr(self, k, v)

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
            if t in self.opcode_to_int:
                f.write(bytes_from_int(self.opcode_to_int[t]))
            elif ("OP_%s" % t) in self.opcode_to_int:
                f.write(bytes_from_int(self.opcode_to_int["OP_%s" % t]))
            elif t.startswith("0x"):
                d = binascii.unhexlify(t[2:])
                f.write(d)
            else:
                v = self.compile_expression(t)
                self.dataCodec.write_push_data([v], f)
        return f.getvalue()

    def disassemble_for_opcode_data(self, opcode, data):
        # TODO: check data for int or string representation
        if data is not None and len(data) > 0:
            return "[%s]" % binascii.hexlify(data).decode("utf8")
        return self.int_to_opcode.get(opcode, "???")

    def opcode_list(self, script):
        """Disassemble the given script. Returns a list of opcodes."""
        opcodes = []
        pc = 0
        try:
            while pc < len(script):
                opcode, data, new_pc = self.dataCodec.get_opcode(script, pc)
                opcodes.append(self.disassemble_for_opcode_data(opcode, data))
                pc = new_pc
        except ScriptError:
            opcodes.append(binascii.hexlify(script[new_pc:]).decode("utf8"))

        return opcodes

    def disassemble(self, script):
        """Disassemble the given script. Returns a string."""
        return ' '.join(self.opcode_list(script))

    def delete_subscript(self, script, subscript):
        """
        Returns a script with the given subscript removed. The subscript
        must appear in the main script aligned to opcode boundaries for it
        to be removed.
        """
        new_script = bytearray()
        pc = 0
        for opcode, data, pc, new_pc in self.get_opcodes(script):
            section = script[pc:new_pc]
            if section != subscript:
                new_script.extend(section)
        return bytes(new_script)
