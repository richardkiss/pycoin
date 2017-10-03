from ..bitcoin.Solver import BitcoinSolver
from pycoin.satoshi.flags import SIGHASH_ALL, SIGHASH_FORKID

from .SolutionChecker import BCashSolutionChecker


class BCashSolver(BitcoinSolver):
    SolutionChecker = BCashSolutionChecker

    def solve(self, *args, **kwargs):
        if kwargs.get("hash_type") is None:
            kwargs["hash_type"] = SIGHASH_ALL
        kwargs["hash_type"] |= SIGHASH_FORKID
        return super(BCashSolver, self).solve(*args, **kwargs)
