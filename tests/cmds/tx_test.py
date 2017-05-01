#!/usr/bin/env python

import unittest
import os
import sys
import tempfile

from pycoin.serialize import h2b

from .ToolTest import ToolTest

# binary data with GPG-encrypted WIF KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn for secret exponent 1
WIF_1_GPG = h2b(
    "8c0d040303026c3030b7518a94eb60c950bc87ab26f0604a37f247f74f88deda10b180bb807"
    "2879b728b8f056808baea0c8e511e7cf2eba77cce937d2f69a67a79e163bf70b57113d27cb6"
    "a1c2390a1e8069b447c34a7c9b5ba268c2beedd85b50")


class TxTest(ToolTest):

    def test_tx_fetch(self):
        self.launch_tool("tx.py 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")

    def test_tx_build(self):
        self.launch_tool("tx.py 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098/0/410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac/5000000000 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T")

    def test_tx_sign(self):
        self.launch_tool("tx.py 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098/0/210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac/5000000000 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")

    def test_tx_from_hex(self):
        # this hex represents a coinbase Tx to KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
        self.launch_tool("tx.py 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0100f2052a0100000023210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac00000000")

    def test_tx_with_gpg(self):
        gpg_wif = tempfile.NamedTemporaryFile(suffix=".gpg")
        gpg_wif.write(WIF_1_GPG)
        gpg_wif.flush()
        self.launch_tool(args=["tx.py", "5564224b6c01dbc2bfad89bfd8038bc2f4ca6c55eb660511d7151d71e4b94b6d/0/210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac/5000000000", "1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T", "-f", gpg_wif.name, "-g", "--batch --passphrase=foo"])


def main():
    unittest.main()

if __name__ == "__main__":
    main()
