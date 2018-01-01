from ...intbytes import byte2int, indexbytes

from ..SolutionChecker import SolutionChecker

from pycoin.satoshi.flags import VERIFY_P2SH

from .ScriptTools import BitcoinScriptTools


OP_EQUAL = BitcoinScriptTools.int_for_opcode("OP_EQUAL")
OP_HASH160 = BitcoinScriptTools.int_for_opcode("OP_HASH160")


class P2SChecker(SolutionChecker):

    @classmethod
    def is_pay_to_script_hash(class_, script_public_key):
        return (len(script_public_key) == 23 and byte2int(script_public_key) == OP_HASH160 and
                indexbytes(script_public_key, -1) == OP_EQUAL)

    @classmethod
    def script_hash_from_script(class_, puzzle_script):
        if class_.is_pay_to_script_hash(puzzle_script):
            return puzzle_script[2:-1]
        return False

    def p2s_program_tuple(self, tx_context, puzzle_script, solution_stack, flags, sighash_f):
        if flags & VERIFY_P2SH and self.is_pay_to_script_hash(puzzle_script):
            self._check_script_push_only(tx_context.solution_script)
            puzzle_script, solution_stack = solution_stack[-1], solution_stack[:-1]
            return puzzle_script, solution_stack, flags & ~VERIFY_P2SH, sighash_f
