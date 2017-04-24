"""
# BRAIN DAMAGE BELOW HERE

def build_microcode(class_):
    class_.INSTRUCTION_LOOKUP = make_instruction_lookup(class_.OPCODE_LIST)


def make_variable_decoder(dec_length):
    def decode_OP_PUSHDATA(script, pc):
        pc += 1
        size_blob = script[pc:pc+dec_length]
        if len(size_blob) < dec_length:
            raise ScriptError("unexpected end of data when size expected", errno.BAD_OPCODE)
        size = from_bytes(size_blob, byteorder="little")
        pc += dec_length
        return size, pc
    return decode_OP_PUSHDATA


OPCODE_CONST_LIST = [("OP_%d" % i, IntStreamer.int_to_script_bytes(i)) for i in range(17)] + [
    ("OP_1NEGATE", IntStreamer.int_to_script_bytes(-1))]
OPCODE_SIZED_LIST = [("OP_PUSH_%d" % i, i) for i in range(1, 76)]
OPCODE_VARIABLE_LIST = [
    ("OP_PUSHDATA1", 0, (1 << 8)-1, lambda d: struct.pack("<B", d), make_variable_decoder(1)),
    ("OP_PUSHDATA2", (1 << 8)-1, (1 << 16)-1, lambda d: struct.pack("<H", d), make_variable_decoder(2)),
    ("OP_PUSHDATA4", (1 << 16)-1, (1 << 32)-1, lambda d: struct.pack("<L", d), make_variable_decoder(4)),
]

OPCODE_LOOKUP = dict(o for o in opcodes.OPCODE_LIST)

build_microcode(VM)

VM.ScriptCodec = ScriptCodec(
    OPCODE_CONST_LIST, OPCODE_SIZED_LIST, OPCODE_VARIABLE_LIST, OPCODE_LOOKUP)

from .ScriptTools import ScriptTools

ScriptTools = ScriptTools(opcodes.OPCODE_LIST, IntStreamer, VM.ScriptCodec)

VM.bin_script = ScriptTools.compile_push_data_list
"""
from .Bitcoin import BitcoinScriptTools as ScriptTools

from .Bitcoin import BitcoinVM as VM
