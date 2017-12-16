
from .SolutionChecker import BGoldSolutionChecker
from .Solver import BGoldSolver

from pycoin.tx.Tx import Tx as BaseTx


class Tx(BaseTx):
    Solver = BGoldSolver
    SolutionChecker = BGoldSolutionChecker
