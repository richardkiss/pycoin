from ...tx.script import errno
from ...tx.script import ScriptError

from ..bitcoin.SolutionChecker import BitcoinSolutionChecker


SIGHASH_FORKID = 0x40


class BCashSolutionChecker(BitcoinSolutionChecker):
    def signature_hash(self, tx_out_script, unsigned_txs_out_idx, hash_type):
        """
        Return the canonical hash for a transaction. We need to
        remove references to the signature, since it's a signature
        of the hash before the signature is applied.

        tx_out_script: the script the coins for unsigned_txs_out_idx are coming from
        unsigned_txs_out_idx: where to put the tx_out_script
        hash_type: one of SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL,
        optionally bitwise or'ed with SIGHASH_ANYONECANPAY
        """

        if hash_type & SIGHASH_FORKID != SIGHASH_FORKID:
            raise ScriptError()

        return self.signature_for_hash_type_segwit(tx_out_script, unsigned_txs_out_idx, hash_type)


def check_solution(tx, tx_in_idx, flags=None, traceback_f=None, solution_checker=BCashSolutionChecker):
    sc = solution_checker(tx)
    tx_context = sc.tx_context_for_idx(tx_in_idx)
    sc.check_solution(tx_context, flags, traceback_f=traceback_f)


def is_signature_ok(tx, tx_in_idx, flags=None, solution_checker=BCashSolutionChecker, **kwargs):
    sc = solution_checker(tx)
    return sc.is_signature_ok(tx_in_idx, **kwargs)


def bad_signature_count(tx, flags=None, solution_checker=BCashSolutionChecker, **kwargs):
    sc = solution_checker(tx)
    return sum(0 if sc.is_signature_ok(idx, **kwargs) else 1 for idx in range(len(tx.txs_in)))
