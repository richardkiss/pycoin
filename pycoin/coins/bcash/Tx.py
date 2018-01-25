
from .SolutionChecker import BcashSolutionChecker
from .Solver import BcashSolver

from pycoin.tx.Tx import Tx as BaseTx


class Tx(BaseTx):
    Solver = BcashSolver
    SolutionChecker = BcashSolutionChecker
