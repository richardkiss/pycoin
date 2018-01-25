
from .SolutionChecker import BgoldSolutionChecker
from .Solver import BgoldSolver

from pycoin.tx.Tx import Tx as BaseTx


class Tx(BaseTx):
    Solver = BgoldSolver
    SolutionChecker = BgoldSolutionChecker
