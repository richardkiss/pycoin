import io

from pycoin.coins.bitcoin.Tx import Tx as BaseTx
from pycoin.convention import SATOSHI_PER_COIN
from pycoin.satoshi.satoshi_struct import stream_struct

from .hash import sha256
from .Solver import GroestlcoinSolver as Solver
from .SolutionChecker import GroestlcoinSolutionChecker as SolutionChecker


class Tx(BaseTx):
    SolutionChecker = SolutionChecker
    Solver = Solver

    MAX_MONEY = 105000000 * SATOSHI_PER_COIN

    def hash(self, hash_type=None):
        s = io.BytesIO()
        self.stream(s, include_witness_data=False)
        if hash_type is not None:
            stream_struct("L", s, hash_type)
        return sha256(s.getvalue())

    def w_hash(self):
        return sha256(self.as_bin())

    def blanked_hash(self):
        s = io.BytesIO()
        self.stream(s, blank_solutions=True)
        return sha256(s.getvalue())
