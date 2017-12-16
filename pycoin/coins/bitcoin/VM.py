
from pycoin.coins.SolutionChecker import ScriptError
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.satoshi import errno, opcodes
from pycoin.satoshi.IntStreamer import IntStreamer
from pycoin.satoshi.flags import VERIFY_MINIMALDATA

from .ScriptStreamer import BitcoinScriptStreamer

from pycoin.vm.VM import VM


from .make_instruction_lookup import make_instruction_lookup


class BitcoinVM(VM):
    IntStreamer = IntStreamer

    VM_FALSE = IntStreamer.int_to_script_bytes(0)
    VM_TRUE = IntStreamer.int_to_script_bytes(1)

    INSTRUCTION_LOOKUP = make_instruction_lookup(opcodes.OPCODE_LIST)
    ScriptStreamer = BitcoinScriptStreamer

    def pop_int(self):
        return self.IntStreamer.int_from_script_bytes(self.pop(), require_minimal=self.flags & VERIFY_MINIMALDATA)

    def pop_nonnegative(self):
        v = self.pop_int()
        if v < 0:
            raise ScriptError("unexpectedly got negative value", errno.INVALID_STACK_OPERATION)
        return v

    def push_int(self, v):
        self.append(self.IntStreamer.int_to_script_bytes(v))

    @classmethod
    def bool_from_script_bytes(class_, v, require_minimal=False):
        v = class_.IntStreamer.int_from_script_bytes(v, require_minimal=require_minimal)
        if require_minimal:
            if v not in (class_.VM_FALSE, class_.VM_TRUE):
                raise ScriptError("non-minimally encoded", errno.UNKNOWN_ERROR)
        return bool(v)

    @classmethod
    def bool_to_script_bytes(class_, v):
        return class_.VM_TRUE if v else class_.VM_FALSE

    @classmethod
    def generator_for_signature_type(class_, signature_type):
        return secp256k1_generator
