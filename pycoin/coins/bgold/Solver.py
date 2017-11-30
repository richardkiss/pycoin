from ..bitcoin.Solver import BitcoinSolver
from pycoin.satoshi.flags import SIGHASH_ALL, SIGHASH_FORKID

from .SolutionChecker import BGoldSolutionChecker


class BGoldSolver(BitcoinSolver):
    SolutionChecker = BGoldSolutionChecker

    def solve(self, *args, **kwargs):
        if kwargs.get("hash_type") is None:
            kwargs["hash_type"] = SIGHASH_ALL
        kwargs["hash_type"] |= SIGHASH_FORKID
        return super(BGoldSolver, self).solve(*args, **kwargs)
