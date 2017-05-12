from .ScriptTools import BitcoinScriptTools

from ...tx.script.BaseSolutionChecker import SolutionChecker
from ...intbytes import byte2int, indexbytes

from .VM import BitcoinVM


def make_solution_checker():
    V0_len20_prefix = BitcoinScriptTools.compile("OP_DUP OP_HASH160")
    V0_len20_postfix = BitcoinScriptTools.compile("OP_EQUALVERIFY OP_CHECKSIG")
    OP_EQUAL = BitcoinScriptTools.int_for_opcode("OP_EQUAL")
    OP_HASH160 = BitcoinScriptTools.int_for_opcode("OP_HASH160")

    class BitcoinSolutionChecker(SolutionChecker):
        VM = BitcoinVM

        @classmethod
        def is_pay_to_script_hash(class_, script_public_key):
            return (len(script_public_key) == 23 and byte2int(script_public_key) == OP_HASH160 and
                    indexbytes(script_public_key, -1) == OP_EQUAL)

        @classmethod
        def _puzzle_script_for_len20_segwit(class_, witness_program):
            return V0_len20_prefix + class_.VM.dataCodec.compile_push_data(
                witness_program) + V0_len20_postfix

    return BitcoinSolutionChecker


BitcoinSolutionChecker = make_solution_checker()
