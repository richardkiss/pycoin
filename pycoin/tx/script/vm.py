
import logging

from . import opcodes

from .tools import get_opcode

from .microcode import MICROCODE_LOOKUP, VCH_TRUE, make_bool

from .signing import verify_script_signature

VERIFY_OPS = frozenset((opcodes.OPCODE_TO_INT[s] for s in "OP_NUMEQUALVERIFY OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_VERIFY OP_CHECKMULTISIGVERIFY".split()))

INVALID_OPCODE_VALUES = frozenset((opcodes.OPCODE_TO_INT[s] for s in "OP_CAT OP_SUBSTR OP_LEFT OP_RIGHT OP_INVERT OP_AND OP_OR OP_XOR OP_2MUL OP_2DIV OP_MUL OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT".split()))

class ScriptError(Exception): pass

def eval_script(script, tx_to, n_in, hash_type, stack=[], alt_stack=[]):
    if len(script) > 10000:
        return False

    pc = 0
    begin_code_hash = pc
    if_condition = None # or True or False

    try:
        while pc < len(script):
            opcode, data, pc = get_opcode(script, pc)
            if len(data) > 0:
                stack.append(data)
                continue

            # deal with if_condition first

            if if_condition is not None:
                if opcode == OP_ELSE:
                    if_condition = not if_condition
                    continue
                if opcode == OP_ENDIF:
                    if_condition = None
                    continue
                if not if_condition:
                    continue
                if opcode in (OP_IF, OP_NOTIF):
                    if_condition = (stack.pop() == VCH_TRUE)
                    continue

            if opcode == opcodes.OP_CODESEPARATOR:
                begin_code_hash = pc - 1
                continue

            if opcode in INVALID_OPCODE_VALUES:
                raise ScriptError("invalid opcode %s at %d" % (opcodes.INT_TO_OPCODE[opcode], pc-1))

            if opcode in MICROCODE_LOOKUP:
                MICROCODE_LOOKUP[opcode](stack)
                if opcode in VERIFY_OPS:
                    v = stack.pop()
                    if v != VCH_TRUE:
                        raise ScriptError("VERIFY failed at %d" % (pc-1))
                continue

            if opcode == opcodes.OP_TOALTSTACK:
                altstack.append(stack.pop())
                continue

            if opcode == opcodes.OP_FROMALTSTACK:
                stack.append(altstack.pop())
                continue

            if opcode >= opcodes.OP_1NEGATE and opcode <= opcodes.OP_16:
                s.push(opcode + 1 - OP_1)
                continue

            if opcode in (opcodes.OP_ELSE, opcodes.OP_ENDIF):
                raise ScriptError("%s without OP_IF" % opcodes.INT_TO_OPCODE[opcode])

            if opcode in (opcodes.OP_CHECKSIG, opcodes.OP_CHECKSIGVERIFY):
                public_key_blob = stack.pop()
                sig_blob = stack.pop()
                subscript = script[begin_code_hash:]
                v = verify_script_signature(script, tx_to, n_in, public_key_blob, sig_blob, subscript, hash_type)
                v = make_bool(v)
                stack.append(v)
                if opcode == opcodes.OP_CHECKSIGVERIFY:
                    if stack.pop() != VCH_TRUE:
                        raise ScriptError("VERIFY failed at %d" % pc-1)
                continue

            # BRAIN DAMAGE -- does it always get down here for each verify op? I think not
            if opcode in VERIFY_OPS:
                v = stack.pop()
                if v != VCH_TRUE:
                    raise ScriptError("VERIFY failed at %d" % pc-1)

            logging.error("can't execute opcode %s", opcode)

    except Exception:
        logging.exception("script failed")

    return len(stack) != 0

def verify_script(script_signature, script_public_key, tx_to, n_in, hash_type=0):
    stack = []
    if not eval_script(script_signature, tx_to, n_in, hash_type, stack):
        logging.debug("script_signature did not evaluate")
        return False
    if not eval_script(script_public_key, tx_to, n_in, hash_type, stack):
        logging.debug("script_public_key did not evaluate")
        return False

    return stack[-1] == VCH_TRUE
