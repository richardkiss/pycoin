#!/usr/bin/env python

import unittest
import os
import sys
import tempfile

from pycoin.serialize import h2b

# binary data with GPG-encrypted WIF KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn for secret exponent 1
WIF_1_GPG = h2b(
    "8c0d040303026c3030b7518a94eb60c950bc87ab26f0604a37f247f74f88deda10b180bb807"
    "2879b728b8f056808baea0c8e511e7cf2eba77cce937d2f69a67a79e163bf70b57113d27cb6"
    "a1c2390a1e8069b447c34a7c9b5ba268c2beedd85b50")

class ScriptsTest(unittest.TestCase):

    def launch_tool(self, tool):
        # set
        python_path = sys.executable
        script_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pycoin", "scripts"))
        cwd = os.getcwd()
        os.chdir(script_dir)
        tool = "%s %s" % (python_path, tool)
        os.environ["PYCOIN_SERVICE_PROVIDERS"] = "BLOCKR_IO:BLOCKCHAIN_INFO:BITEASY:BLOCKEXPLORER"
        r = os.system(tool)
        os.chdir(cwd)
        assert r == 0

    def set_cache_dir(self):
        temp_dir = tempfile.mkdtemp()
        os.environ["PYCOIN_CACHE_DIR"] = temp_dir
        return temp_dir

    def test_fetch_unspent(self):
        self.launch_tool("fetch_unspent.py 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T")

    def test_ku(self):
        self.launch_tool("ku.py 1")
        self.launch_tool("ku.py 2")
        self.launch_tool("ku.py -a 1")
        self.launch_tool("ku.py -W 1")
        self.launch_tool("ku.py P:foo")
        self.launch_tool("ku.py -w P:foo -s 5-10")
        self.launch_tool("ku.py -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n BTC -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n XTN -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n LTC -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n XLT -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n VIA -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n TVI -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n DRK -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n MEC -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n DOGE -j -w P:foo -s 5-10")
        self.launch_tool("ku.py -n BC -j -w P:foo -s 5-10")
        self.launch_tool("ku.py xprv9s21ZrQH143K31AgNK5pyVvW23gHnkBq2wh5aEk6g1s496M8ZMjxncCKZKgb5jZoY5eSJMJ2Vbyvi2hbmQnCuHBujZ2WXGTux1X2k9Krdtq")
        self.launch_tool("ku.py -n XTN -s 0/0-2 ttub4XNESS7BCg9c2MhXxffDq3JB8rpDKygicxpXmCtUt83VVnSmm7KcRNkH7CFaymFLU9hDznwk13FxBms3T26JuoBDGAgqr6iyPzYtu7WSNNm -a")
        self.launch_tool("ku.py --override-network XTN -s 0/0-2 ttub4XNESS7BCg9c2MhXxffDq3JB8rpDKygicxpXmCtUt83VVnSmm7KcRNkH7CFaymFLU9hDznwk13FxBms3T26JuoBDGAgqr6iyPzYtu7WSNNm -a")

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
        #gpg_dir = tempfile.mkdtemp()
        #import pdb; pdb.set_trace()
        #os.environ["GNUPGHOME"] = gpg_dir
        ##f = open(os.path.join(gpg_dir, "gpg.conf"), "w")
        #f.write("use-agent\n")
        #f.close()
        gpg_wif = tempfile.NamedTemporaryFile(suffix=".gpg")
        gpg_wif.write(WIF_1_GPG)
        gpg_wif.flush()
        self.launch_tool("tx.py 5564224b6c01dbc2bfad89bfd8038bc2f4ca6c55eb660511d7151d71e4b94b6d/0/210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac/5000000000 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T -f %s -g'--passphrase foo'" % gpg_wif.name)

    def test_genwallet(self):
        self.launch_tool("genwallet.py -u")

    def test_cache_tx(self):
        the_dir = self.set_cache_dir()
        tx_id = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
        self.launch_tool("cache_tx.py %s" % tx_id)
        self.assertTrue(os.path.exists(os.path.join(the_dir, "txs", "%s_tx.bin" % tx_id)))

def main():
    unittest.main()

if __name__ == "__main__":
    main()
