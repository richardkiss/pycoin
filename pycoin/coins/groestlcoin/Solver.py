from pycoin.coins.bitcoin.Solver import BitcoinSolver
from .SolutionChecker import GroestlcoinSolutionChecker


class GroestlcoinSolver(BitcoinSolver):
    SolutionChecker = GroestlcoinSolutionChecker
