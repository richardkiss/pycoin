from __future__ import annotations

from typing import Any, Callable

from pycoin.coins.SolutionChecker import ScriptError
from pycoin.satoshi import intops, stackops, checksigops, miscops
from pycoin.satoshi import errno

from .ScriptStreamer import BitcoinScriptStreamer


def _make_bad_instruction(v: int) -> Callable[[Any], None]:
    def f(vm_state: Any) -> None:
        raise ScriptError(
            "invalid instruction x%02x at %d" % (v, vm_state.pc), errno.BAD_OPCODE
        )

    return f


def _collect_opcodes(module: Any) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k in dir(module):
        if k.startswith("do_OP"):
            d[k[3:]] = getattr(module, k)
    return d


def _no_op(vm: Any) -> None:
    pass


def make_instruction_lookup(opcode_pairs: list[tuple[str, int]]) -> list[Callable[[Any], None]]:
    OPCODE_DATA_LIST = list(BitcoinScriptStreamer.data_opcodes)

    # start with all opcodes invalid
    instruction_lookup: list[Callable[[Any], None]] = [_make_bad_instruction(i) for i in range(256)]

    for i in OPCODE_DATA_LIST:
        if i is not None:
            instruction_lookup[i] = _no_op
    opcode_lookups: dict[str, Any] = {}
    opcode_lookups.update(_collect_opcodes(checksigops))
    opcode_lookups.update(_collect_opcodes(intops))
    opcode_lookups.update(_collect_opcodes(stackops))
    opcode_lookups.update(_collect_opcodes(miscops))
    opcode_lookups.update(miscops.extra_opcodes())
    for opcode_name, opcode_value in opcode_pairs:
        if opcode_name in opcode_lookups:
            instruction_lookup[opcode_value] = opcode_lookups[opcode_name]
    return instruction_lookup
