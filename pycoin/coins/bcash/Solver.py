from ..bitcoin.Solver import BitcoinSolver
from pycoin.satoshi.flags import SIGHASH_ALL, SIGHASH_FORKID

from .SolutionChecker import BcashSolutionChecker


class BcashSolver(BitcoinSolver):
    SolutionChecker = BcashSolutionChecker

    def solve(self, *args, **kwargs):
        if kwargs.get("hash_type") is None:
            kwargs["hash_type"] = SIGHASH_ALL
        kwargs["hash_type"] |= SIGHASH_FORKID
        return super(BcashSolver, self).solve(*args, **kwargs)
