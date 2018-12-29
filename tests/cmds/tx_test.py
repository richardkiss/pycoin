import unittest
import os
import tempfile

from pycoin.cmds import tx
from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.btc import network

from .ToolTest import ToolTest


# BRAIN DAMAGE
Tx = network.tx


class TxTest(ToolTest):

    @classmethod
    def setUpClass(cls):
        cls.parser = tx.create_parser()
        cls.tool_name = "tx"

    def test_tx_fetch_unspent(self):
        P2 = "76a914b3407d4b4d1fca87fb930abe3fa6c2baed6e6fd888ac"
        FETCH_UNSPENT_EXPECT = [
            "5fd3d8275afb5b5cc202ae8480daefa4fe16d0cf480ce78545d6dc06c6fb101a/1/%s/1/0/0/0" % P2,
            "b9a84cffd3766bb642a697065b477eed032e36c377db80faac79b18e61b43b0d/1/%s/1/0/0/0" % P2,
            "0986d70aaa03213135998cf1a9b8a33012c033c6607584e84b8ae33d49fadce3/0/%s/1/0/0/0" % P2,
            "d658ab87cc053b8dbcfd4aa2717fd23cc3edfe90ec75351fadd6a0f7993b461d/7/%s/911/0/0/0" % P2,
        ]
        output = self.launch_tool("tx -i 1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1").split("\n")
        for k in FETCH_UNSPENT_EXPECT:
            self.assertIn(k, output)

    def test_cache_tx(self):
        the_dir = self.set_cache_dir()
        tx = Tx.from_hex(
            "01000000010000000000000000000000000000000000000000000000000000000000000000"
            "ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a"
            "2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781"
            "e62294721166bf621e73a82cbf2342c858eeac00000000")
        self.launch_tool("tx -C %s --db %s" % (tx.id(), tx.as_hex()), env=dict(PYCOIN_CACHE_DIR=the_dir))
        self.assertTrue(os.path.exists(os.path.join(the_dir, "txs", "%s_tx.bin" % tx.id())))

    def test_pay_to_script_file(self):
        the_dir = self.set_cache_dir()
        p2sh_file = tempfile.NamedTemporaryFile()
        p2sh_file.write(
            "52210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c60"
            "47f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52102f9308a019258"
            "c31049344f85f89d5229b531c845836f99b08601f113bce036f953ae\n".encode("utf8"))
        p2sh_file.write(
            "53210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c60"
            "47f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52102f9308a019258"
            "c31049344f85f89d5229b531c845836f99b08601f113bce036f953ae\n".encode("utf8"))
        p2sh_file.flush()
        tx_source_hex = (
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0"
            "0ffffffff0200f902950000000017a91415fc0754e73eb85d1cbce08786fadb7320ecb8dc8700f90295"
            "0000000017a914594f349df0bac3084ffea8a477bba5f03dcd45078700000000")
        self.launch_tool("tx -C %s" % tx_source_hex)
        tx_to_sign = (
            "01000000020a316ea8980ef9ba02f4e6637c88229bf059f39b06238d48d06a8e"
            "f672aea2bb0000000000ffffffff0a316ea8980ef9ba02f4e6637c88229bf059"
            "f39b06238d48d06a8ef672aea2bb0100000000ffffffff01f0ca052a01000000"
            "1976a914751e76e8199196d454941c45d1b3a323f1433bd688ac0000000000f9"
            "02950000000017a91415fc0754e73eb85d1cbce08786fadb7320ecb8dc8700f9"
            "02950000000017a914594f349df0bac3084ffea8a477bba5f03dcd450787")
        wifs = ' '.join(network.keys.private(_).wif() for _ in (1, 2, 3))
        signed = tempfile.mktemp(suffix=".hex")
        self.launch_tool("tx -a -P %s --db %s %s %s -o %s" % (
            p2sh_file.name, tx_source_hex, tx_to_sign, wifs, signed), env=dict(PYCOIN_CACHE_DIR=the_dir))
        tx = Tx.from_hex(open(signed).read())
        self.assertEqual(tx.id(), "9d991ddccf77e33cb4584e4fc061a36da0da43589232b2e78a1aa0748ac3254b")

    def test_tx_with_gpg(self):
        # binary data with GPG-encrypted WIF KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn for secret exponent 1
        WIF_1_GPG = h2b(
            "8c0d040303026c3030b7518a94eb60c950bc87ab26f0604a37f247f74f88deda10b180bb807"
            "2879b728b8f056808baea0c8e511e7cf2eba77cce937d2f69a67a79e163bf70b57113d27cb6"
            "a1c2390a1e8069b447c34a7c9b5ba268c2beedd85b50")
        gpg_wif = tempfile.NamedTemporaryFile(suffix=".gpg")
        gpg_wif.write(WIF_1_GPG)
        gpg_wif.flush()
        output_file = tempfile.NamedTemporaryFile(suffix=".hex")
        self.launch_tool(
            args=["tx",
                  "5564224b6c01dbc2bfad89bfd8038bc2f4ca6c55eb660511d7151d71e4b94b6d/0/"
                  "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac/5000000000",
                  "1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T", "-f", gpg_wif.name, "-g", "--batch --passphrase=foo",
                  "-o", output_file.name])
        d = open(output_file.name).read()
        tx = Tx.from_hex(d)
        self.assertEqual(tx.id(), "c52b0c66cff6147b99acb29389343f6eae68c29faf2186fa8c1613d615b217e8")


def main():
    unittest.main()


if __name__ == "__main__":
    main()
