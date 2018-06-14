import struct

from pycoin.coins.SolutionChecker import ScriptError
from pycoin.satoshi import errno, opcodes
from pycoin.satoshi.IntStreamer import IntStreamer
from pycoin.vm.ScriptStreamer import ScriptStreamer


def make_opcode_const_list():
    return [("OP_%d" % i, IntStreamer.int_to_script_bytes(i)) for i in range(17)] + [
            ("OP_1NEGATE", IntStreamer.int_to_script_bytes(-1))]


def make_opcode_sized_list():
    return [("OP_PUSH_%d" % i, i) for i in range(1, 76)]


def make_opcode_variable_list():
    def make_variable_decoder(struct_data):
        struct_size = struct.calcsize(struct_data)

        def decode_OP_PUSHDATA(script, pc):
            pc += 1
            try:
                size = struct.unpack(struct_data, script[pc:pc+struct_size])[0]
            except Exception:
                return 0, pc
            pc += struct_size
            return size, pc
        return decode_OP_PUSHDATA

    OPCODE_VARIABLE_LIST = [
        ("OP_PUSHDATA1", (1 << 8)-1, lambda d: struct.pack("<B", d), make_variable_decoder("<B")),
        ("OP_PUSHDATA2", (1 << 16)-1, lambda d: struct.pack("<H", d), make_variable_decoder("<H")),
        ("OP_PUSHDATA4", (1 << 32)-1, lambda d: struct.pack("<L", d), make_variable_decoder("<L"))
    ]
    return OPCODE_VARIABLE_LIST


def non_minimal_f(msg):
    raise ScriptError(msg, errno.MINIMALDATA)


def make_script_streamer():
    OPCODE_CONST_LIST = make_opcode_const_list()
    OPCODE_SIZED_LIST = make_opcode_sized_list()
    OPCODE_VARIABLE_LIST = make_opcode_variable_list()
    OPCODE_LOOKUP = dict(o for o in opcodes.OPCODE_LIST)

    return ScriptStreamer(
        OPCODE_CONST_LIST, OPCODE_SIZED_LIST, OPCODE_VARIABLE_LIST, OPCODE_LOOKUP, non_minimal_f)


BitcoinScriptStreamer = make_script_streamer()
