
from .SolutionChecker import BgoldSolutionChecker
from .Solver import BgoldSolver

from pycoin.coins.bitcoin.Tx import Tx as BaseTx


class Tx(BaseTx):
    Solver = BgoldSolver
    SolutionChecker = BgoldSolutionChecker
