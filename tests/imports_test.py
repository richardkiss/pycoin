#!/usr/bin/env python

import unittest


class ImportsTest(unittest.TestCase):

    def test_import_tx(self):
        import pycoin.tx.TxIn


if __name__ == '__main__':
    unittest.main()
