from __future__ import annotations

from typing import Any

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

    def pop_int(self) -> int:
        return self.IntStreamer.int_from_script_bytes(  # type: ignore[no-any-return]
            self.pop(), require_minimal=bool(self.flags & VERIFY_MINIMALDATA)
        )

    def pop_nonnegative(self) -> int:
        v = self.pop_int()
        if v < 0:
            raise ScriptError(
                "unexpectedly got negative value", errno.INVALID_STACK_OPERATION
            )
        return v

    def push_int(self, v: int) -> None:
        self.append(self.IntStreamer.int_to_script_bytes(v))

    @classmethod
    def bool_from_script_bytes(class_: type[BitcoinVM], v: bytes, require_minimal: bool = False) -> bool:  # type: ignore[override]
        int_v = class_.IntStreamer.int_from_script_bytes(v, require_minimal=require_minimal)
        if require_minimal:
            if int_v not in (class_.VM_FALSE, class_.VM_TRUE):
                raise ScriptError("non-minimally encoded", errno.UNKNOWN_ERROR)
        return bool(int_v)

    @classmethod
    def bool_to_script_bytes(class_: type[BitcoinVM], v: Any) -> bytes:  # type: ignore[override]
        return class_.VM_TRUE if v else class_.VM_FALSE

    @classmethod
    def generator_for_signature_type(class_: type[BitcoinVM], signature_type: int) -> Any:  # type: ignore[override]
        return secp256k1_generator
