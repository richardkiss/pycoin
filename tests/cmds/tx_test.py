import unittest
import os
import sys
import tempfile

from pycoin.cmds import tx
from pycoin.serialize import h2b
from pycoin.tx.Tx import Tx

from .ToolTest import ToolTest

# binary data with GPG-encrypted WIF KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn for secret exponent 1
WIF_1_GPG = h2b(
    "8c0d040303026c3030b7518a94eb60c950bc87ab26f0604a37f247f74f88deda10b180bb807"
    "2879b728b8f056808baea0c8e511e7cf2eba77cce937d2f69a67a79e163bf70b57113d27cb6"
    "a1c2390a1e8069b447c34a7c9b5ba268c2beedd85b50")


class TxTest(ToolTest):

    @classmethod
    def setUpClass(cls):
        cls.parser = tx.create_parser()
        cls.tool_name = "tx"

    def invoke_tool(self, args):
        tx.tx(self.parser.parse_args(args[1:]), self.parser)

    def test_tx_fetch(self):
        self.launch_tool("tx 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")

    def test_tx_fetch_unspent(self):
        P2 = "76a914cd5dc792f0abb0aa8ba4ca36c9fe5eda8e495ff988ac"
        FETCH_UNSPENT_EXPECT = [
            "3a1e5271dd30a7217059151bd455ba8ede466ce70f9753383db88ddb449f1d84/0/%s/100000/0/0/0" % P2,
            "86f095d56bb5de23c7d0200e48c5bdbf45578a2719bf00eb5084b5b7bda95e09/0/%s/5000000/0/0/0" % P2,
            "82a21bd8110755454bb7d3a37ad81889d656c29cb27dd5bfdc5044f2fd36abcb/0/%s/40000/0/0/0" % P2,
            "49f95aa8340f8d791456467abf2a26d551783aea1069f571f5b4087eb8f7f42d/0/%s/164598/0/0/0" % P2
        ]
        output = self.launch_tool("tx -i 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T").split("\n")
        for k in FETCH_UNSPENT_EXPECT:
            self.assertIn(k, output)

    def test_cache_tx(self):
        the_dir = self.set_cache_dir()
        tx_id = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
        self.launch_tool("tx %s" % tx_id)
        self.assertTrue(os.path.exists(os.path.join(the_dir, "txs", "%s_tx.bin" % tx_id)))

    def test_tx_build(self):
        self.launch_tool("tx 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098/0/410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac/5000000000 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T")

    def test_tx_sign(self):
        self.launch_tool("tx 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098/0/210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac/5000000000 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")

    def test_tx_from_hex(self):
        # this hex represents a coinbase Tx to KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
        self.launch_tool("tx 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0100f2052a0100000023210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac00000000")

    def test_tx_with_gpg(self):
        gpg_wif = tempfile.NamedTemporaryFile(suffix=".gpg")
        gpg_wif.write(WIF_1_GPG)
        gpg_wif.flush()
        output_file = tempfile.NamedTemporaryFile(suffix=".hex")
        self.launch_tool(args=["tx", "5564224b6c01dbc2bfad89bfd8038bc2f4ca6c55eb660511d7151d71e4b94b6d/0/210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac/5000000000", "1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T", "-f", gpg_wif.name, "-g", "--batch --passphrase=foo", "-o", output_file.name])
        d = open(output_file.name).read()
        tx = Tx.from_hex(d)
        self.assertEqual(tx.id(), "c52b0c66cff6147b99acb29389343f6eae68c29faf2186fa8c1613d615b217e8")


def main():
    unittest.main()

if __name__ == "__main__":
    main()
