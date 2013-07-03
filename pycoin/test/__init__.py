
import unittest
import doctest
import pycoin.tx.script.microcode

def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite(pycoin.tx.script.microcode))
    return tests
