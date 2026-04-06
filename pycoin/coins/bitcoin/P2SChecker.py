from __future__ import annotations

from typing import Any

from ..SolutionChecker import SolutionChecker

from pycoin.satoshi.flags import VERIFY_P2SH

from .ScriptTools import BitcoinScriptTools


OP_EQUAL = BitcoinScriptTools.int_for_opcode("OP_EQUAL")
OP_HASH160 = BitcoinScriptTools.int_for_opcode("OP_HASH160")


class P2SChecker(SolutionChecker):
    @classmethod
    def is_pay_to_script_hash(class_: type[P2SChecker], script_public_key: bytes) -> bool:
        return (
            len(script_public_key) == 23
            and script_public_key[0] == OP_HASH160
            and script_public_key[-1] == OP_EQUAL
        )

    @classmethod
    def script_hash_from_script(class_: type[P2SChecker], puzzle_script: bytes) -> bytes | bool:
        if class_.is_pay_to_script_hash(puzzle_script):
            return puzzle_script[2:-1]
        return False

    def p2s_program_tuple(
        self,
        tx_context: Any,
        puzzle_script: bytes,
        solution_stack: list[Any],
        flags: int,
        sighash_f: Any,
    ) -> tuple[bytes, list[Any], int, Any] | None:
        if flags & VERIFY_P2SH and self.is_pay_to_script_hash(puzzle_script):
            self._check_script_push_only(tx_context.solution_script)  # type: ignore[attr-defined]
            puzzle_script, solution_stack = solution_stack[-1], solution_stack[:-1]
            return puzzle_script, solution_stack, flags & ~VERIFY_P2SH, sighash_f
        return None
