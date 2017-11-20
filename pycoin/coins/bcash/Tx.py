
from .SolutionChecker import BCashSolutionChecker
from .Solver import BCashSolver

from pycoin.tx.Tx import Tx as BaseTx


class Tx(BaseTx):
    Solver = BCashSolver
    SolutionChecker = BCashSolutionChecker
