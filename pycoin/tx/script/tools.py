
import binascii
import io

from .opcodes import OPCODE_TO_INT, INT_TO_OPCODE

def get_opcode(script, pc):
    opcode = script[pc]
    pc += 1
    data = b''
    if opcode <= OPCODE_TO_INT["OP_PUSHDATA4"]:
        if opcode < OPCODE_TO_INT["OP_PUSHDATA1"]:
            size = opcode
        elif opcode == OPCODE_TO_INT["OP_PUSHDATA1"]:
            size = as_bignum(script[pc])
            pc += 1
        elif opcode == OPCODE_TO_INT["OP_PUSHDATA2"]:
            size = as_bignum(script[pc:pc+2])
            pc += 2
        elif opcode == OPCODE_TO_INT["OP_PUSHDATA4"]:
            size = as_bignum(script[pc:pc+4])
            pc += 4
        data = script[pc:pc+size]
        pc += size
    return opcode, data, pc

def compile(s):
    f = io.BytesIO()
    for t in s.split():
        if t in OPCODE_TO_INT:
            f.write(bytes([OPCODE_TO_INT[t]]))
        else:
            t = binascii.unhexlify(t)
            # BRAIN DAMAGE: if len(t) is too much, we need a different opcode
            f.write(bytes([len(t)]))
            f.write(t)
    return f.getvalue()

def disassemble(script):
    opcodes = []
    pc = 0
    while pc < len(script):
        opcode, data, pc = get_opcode(script, pc)
        if len(data) > 0:
            opcodes.append(binascii.hexlify(data).decode("utf8"))
            continue
        if not opcode in INT_TO_OPCODE:
            logging.info("missing opcode %r", opcode)
            continue
        opcodes.append(INT_TO_OPCODE[opcode])
    return ' '.join(opcodes)
