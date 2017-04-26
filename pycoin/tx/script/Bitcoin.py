import struct

from ...intbytes import from_bytes

from . import intops, stackops, checksigops, miscops

from . import errno
from . import opcodes
from . import ScriptError

from .IntStreamer import IntStreamer
from .ScriptCodec import ScriptCodec
from .ScriptTools import ScriptTools
from .BaseSolutionChecker import SolutionChecker
from .BaseVM import VM


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

BitcoinScriptCodec = ScriptCodec(
    OPCODE_CONST_LIST, OPCODE_SIZED_LIST, OPCODE_VARIABLE_LIST, OPCODE_LOOKUP)


BitcoinScriptTools = ScriptTools(opcodes.OPCODE_LIST, IntStreamer, BitcoinScriptCodec)


OPCODE_DATA_LIST = list(BitcoinScriptCodec.data_opcodes)


def make_bad_instruction(v):
    def f(vm_state):
        raise ScriptError("invalid instruction x%02x at %d" % (v, vm_state.pc), errno.BAD_OPCODE)
    return f


def collect_opcodes(module):
    d = {}
    for k in dir(module):
        if k.startswith("do_OP"):
            d[k[3:]] = getattr(module, k)
    return d


def no_op(vm):
    pass


def make_instruction_lookup(opcode_pairs):
    # start with all opcodes invalid
    instruction_lookup = [make_bad_instruction(i) for i in range(256)]
    for i in OPCODE_DATA_LIST:
        instruction_lookup[i] = no_op
    opcode_lookups = {}
    # BRAIN DAMAGE
    opcode_lookups.update(collect_opcodes(checksigops))
    opcode_lookups.update(collect_opcodes(intops))
    opcode_lookups.update(stackops.all_opcodes())
    opcode_lookups.update(miscops.all_opcodes())
    for opcode_name, opcode_value in opcode_pairs:
        if opcode_name in opcode_lookups:
            instruction_lookup[opcode_value] = opcode_lookups[opcode_name]
    return instruction_lookup


INSTRUCTION_LOOKUP = make_instruction_lookup(opcodes.OPCODE_LIST)


class BitcoinVM(VM):
    INSTRUCTION_LOOKUP = INSTRUCTION_LOOKUP
    ScriptCodec = BitcoinScriptCodec
    dataCodec = BitcoinScriptCodec

    bin_script = BitcoinScriptTools.compile_push_data_list


V0_len20_prefix = BitcoinScriptTools.compile("OP_DUP OP_HASH160")
V0_len20_postfix = BitcoinScriptTools.compile("OP_EQUALVERIFY OP_CHECKSIG")


class BitcoinSolutionChecker(SolutionChecker):
    VM = BitcoinVM

    @classmethod
    def _puzzle_script_for_len20_segwit(class_, witness_program):
        return V0_len20_prefix + class_.VM.dataCodec.compile_push_data(
            witness_program) + V0_len20_postfix
