import struct

from ...tx.script import errno, opcodes, ScriptError

from ...tx.script.IntStreamer import IntStreamer
from ...tx.script.ScriptStreamer import ScriptStreamer


def make_script_streamer():
    def make_variable_decoder(struct_data):
        struct_size = struct.calcsize(struct_data)

        def decode_OP_PUSHDATA(script, pc):
            pc += 1
            try:
                size = struct.unpack(struct_data, script[pc:pc+struct_size])[0]
            except Exception:
                raise ScriptError("unexpected end of data when size expected", errno.BAD_OPCODE)
            pc += struct_size
            return size, pc
        return decode_OP_PUSHDATA

    OPCODE_CONST_LIST = [("OP_%d" % i, IntStreamer.int_to_script_bytes(i)) for i in range(17)] + [
        ("OP_1NEGATE", IntStreamer.int_to_script_bytes(-1))]
    OPCODE_SIZED_LIST = [("OP_PUSH_%d" % i, i) for i in range(1, 76)]
    OPCODE_VARIABLE_LIST = [
        ("OP_PUSHDATA1", (1 << 8)-1, lambda d: struct.pack("<B", d), make_variable_decoder("<B")),
        ("OP_PUSHDATA2", (1 << 16)-1, lambda d: struct.pack("<H", d), make_variable_decoder("<H")),
        ("OP_PUSHDATA4", (1 << 32)-1, lambda d: struct.pack("<L", d), make_variable_decoder("<L"))
    ]

    OPCODE_LOOKUP = dict(o for o in opcodes.OPCODE_LIST)

    return ScriptStreamer(
        OPCODE_CONST_LIST, OPCODE_SIZED_LIST, OPCODE_VARIABLE_LIST, OPCODE_LOOKUP)


BitcoinScriptStreamer = make_script_streamer()
