from .ScriptTools import BitcoinScriptTools

from ...tx.script.BaseSolutionChecker import SolutionChecker

from .VM import BitcoinVM


def make_solution_checker():
    V0_len20_prefix = BitcoinScriptTools.compile("OP_DUP OP_HASH160")
    V0_len20_postfix = BitcoinScriptTools.compile("OP_EQUALVERIFY OP_CHECKSIG")

    class BitcoinSolutionChecker(SolutionChecker):
        VM = BitcoinVM

        @classmethod
        def _puzzle_script_for_len20_segwit(class_, witness_program):
            return V0_len20_prefix + class_.VM.dataCodec.compile_push_data(
                witness_program) + V0_len20_postfix

    return BitcoinSolutionChecker


BitcoinSolutionChecker = make_solution_checker()
