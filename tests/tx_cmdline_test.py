#!/usr/bin/env python

import unittest
import os
import subprocess
import sys
import tempfile

TEST_CASES = [
    (
    "tx.py 010000000141045e0ab2b0b82cdefaf9e9a8ca9ec9df17673d6a74e274d0c73ae77d3f131e000000004a493046022100a7f26eda874931999c90f87f01ff1ffc76bcd058fe16137e0e63fdb6a35c2d78022100a61e9199238eb73f07c8f209504c84b80f03e30ed8169edd44f80ed17ddf451901ffffffff010010a5d4e80000001976a9147ec1003336542cae8bded8909cdd6b5e48ba0ab688ac00000000","""\
Version:  1  tx hash 49d2adb6e476fa46d8357babf78b1b501fd39e177ac7833124b3f67b17c40c2a  159 bytes   
TxIn count: 1; TxOut count: 1
Lock time: 0 (valid anytime)
Input:
  0:                          (unknown) from 1e133f7de73ac7d074e2746a3d6717dfc99ecaa8e9f9fade2cb8b0b20a5e0441:0
Output:
  0: 1CZDM6oTttND6WPdt3D6bydo7DYKzd9Qik receives 10000000.00000 mBTC
Total output 10000000.00000 mBTC
including unspents in hex dump since transaction not fully signed
010000000141045e0ab2b0b82cdefaf9e9a8ca9ec9df17673d6a74e274d0c73ae77d3f131e000000004a493046022100a7f26eda874931999c90f87f01ff1ffc76bcd058fe16137e0e63fdb6a35c2d78022100a61e9199238eb73f07c8f209504c84b80f03e30ed8169edd44f80ed17ddf451901ffffffff010010a5d4e80000001976a9147ec1003336542cae8bded8909cdd6b5e48ba0ab688ac00000000
"""
    ),
    (
        "tx.py 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000",
    '''Version:  1  tx hash 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098  134 bytes   
TxIn count: 1; TxOut count: 1
Lock time: 0 (valid anytime)
Input:
  0: COINBASE   50000.00000 mBTC
Output:
  0: 12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX receives  50000.00000 mBTC
Total input   50000.00000 mBTC
Total output  50000.00000 mBTC
Total fees        0.00000 mBTC
01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000
all incoming transaction values validated\n'''
    ),
    (
        "tx.py -C 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000",
        """Version:  1  tx hash 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098  134 bytes   
TxIn count: 1; TxOut count: 1
Lock time: 0 (valid anytime)
Input:
  0: COINBASE   50000.00000 mBTC
Output:
  0: 12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX receives  50000.00000 mBTC
Total input   50000.00000 mBTC\nTotal output  50000.00000 mBTC
Total fees        0.00000 mBTC
01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000
all incoming transaction values validated\n"""
    ),
    (
        "tx.py 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098/0/410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac/5000000000 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T -o tx.bin",
        'all incoming transaction values validated\n'
    ),
    (
        "tx.py tx.bin",
        """\
Version:  1  tx hash 3d36aed60ecb311a55a6329f5c2af785f06e147fc35b7678eb798eca7f603c83  85 bytes   
TxIn count: 1; TxOut count: 1
Lock time: 0 (valid anytime)
Input:
  0: 12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX from 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098:0  50000.00000 mBTC  BAD SIG
Output:
  0: 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T receives  49999.90000 mBTC
Total input   50000.00000 mBTC
Total output  49999.90000 mBTC
Total fees        0.10000 mBTC
including unspents in hex dump since transaction not fully signed
0100000001982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e0000000000ffffffff01f0ca052a010000001976a914cd5dc792f0abb0aa8ba4ca36c9fe5eda8e495ff988ac0000000000f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac
all incoming transaction values validated\n"""
    ),
    (
        "tx.py -C 010000000135b0092a869bca1bc43e1628b3cb9e56ff9099a271fe95755e6f9289cf885b98000000008c4930460221008342b7eee70400acfed8d68be5aa8a6aeb06d7a2b3aef1fab7e4c1e46391efc6022100c0f86ba04f9a43c0d7fc8ab4cf9f3292989d3067f9b04e013c4a96bee87d5e1c014104dbedbe0028b3cbf362cad654c3b3e0902f65004691fa1332e94a31202ff06f4f7e67bd57d278c6a40b1915feb3bfb6850ca3750456e4c9af9db3d57a22b65323ffffffff02102f3504000000001976a9149b92770a85b1252448ec69900e77f1371d6a620188ac4e61bc00000000001976a91491b24bf9f5288532960ac687abb035127b1d28a588ac00000000",
        """Version:  1  tx hash d61aa2a5f5bce59d2a57447134f7ce9ce9d29b5c471f4bf747c43bf82aa26c2a  259 bytes   \nTxIn count: 1; TxOut count: 2\nLock time: 0 (valid anytime)\nInput:\n  0: 1NPcbLkfWU1vFYHBG4i3XB4uQaj4P7PHr2 from 985b88cf89926f5e7595fe71a29990ff569ecbb328163ec41bca9b862a09b035:0\nOutputs:\n  0: 1FBbCJSHrcAwuyEvgjZPpHP8jGAbiCPitz receives    705.94320 mBTC\n  1: 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm receives    123.45678 mBTC\nTotal output    829.39998 mBTC\nincluding unspents in hex dump since transaction not fully signed\n010000000135b0092a869bca1bc43e1628b3cb9e56ff9099a271fe95755e6f9289cf885b98000000008c4930460221008342b7eee70400acfed8d68be5aa8a6aeb06d7a2b3aef1fab7e4c1e46391efc6022100c0f86ba04f9a43c0d7fc8ab4cf9f3292989d3067f9b04e013c4a96bee87d5e1c014104dbedbe0028b3cbf362cad654c3b3e0902f65004691fa1332e94a31202ff06f4f7e67bd57d278c6a40b1915feb3bfb6850ca3750456e4c9af9db3d57a22b65323ffffffff02102f3504000000001976a9149b92770a85b1252448ec69900e77f1371d6a620188ac4e61bc00000000001976a91491b24bf9f5288532960ac687abb035127b1d28a588ac00000000\n"""
    ),
    (
        "tx.py d61aa2a5f5bce59d2a57447134f7ce9ce9d29b5c471f4bf747c43bf82aa26c2a",
        """\
Version:  1  tx hash d61aa2a5f5bce59d2a57447134f7ce9ce9d29b5c471f4bf747c43bf82aa26c2a  259 bytes   
TxIn count: 1; TxOut count: 2
Lock time: 0 (valid anytime)
Input:
  0: 1NPcbLkfWU1vFYHBG4i3XB4uQaj4P7PHr2 from 985b88cf89926f5e7595fe71a29990ff569ecbb328163ec41bca9b862a09b035:0
Outputs:
  0: 1FBbCJSHrcAwuyEvgjZPpHP8jGAbiCPitz receives    705.94320 mBTC
  1: 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm receives    123.45678 mBTC
Total output    829.39998 mBTC
including unspents in hex dump since transaction not fully signed
010000000135b0092a869bca1bc43e1628b3cb9e56ff9099a271fe95755e6f9289cf885b98000000008c4930460221008342b7eee70400acfed8d68be5aa8a6aeb06d7a2b3aef1fab7e4c1e46391efc6022100c0f86ba04f9a43c0d7fc8ab4cf9f3292989d3067f9b04e013c4a96bee87d5e1c014104dbedbe0028b3cbf362cad654c3b3e0902f65004691fa1332e94a31202ff06f4f7e67bd57d278c6a40b1915feb3bfb6850ca3750456e4c9af9db3d57a22b65323ffffffff02102f3504000000001976a9149b92770a85b1252448ec69900e77f1371d6a620188ac4e61bc00000000001976a91491b24bf9f5288532960ac687abb035127b1d28a588ac00000000
"""
    ),
    (
        "tx.py d61aa2a5f5bce59d2a57447134f7ce9ce9d29b5c471f4bf747c43bf82aa26c2a/1/76a91491b24bf9f5288532960ac687abb035127b1d28a588ac/12345678 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T -o tx.bin",
        "all incoming transaction values validated\n"
    ),
    (
        "tx.py tx.bin",
        """\
Version:  1  tx hash ab963a39df0e095bbd76840de90fe208e903d5d43e891ef245b217dbcd29a8a7  85 bytes   
TxIn count: 1; TxOut count: 1
Lock time: 0 (valid anytime)
Input:
  0: 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm from d61aa2a5f5bce59d2a57447134f7ce9ce9d29b5c471f4bf747c43bf82aa26c2a:1    123.45678 mBTC  BAD SIG
Output:
  0: 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T receives    123.35678 mBTC
Total input     123.45678 mBTC
Total output    123.35678 mBTC
Total fees        0.10000 mBTC
including unspents in hex dump since transaction not fully signed
01000000012a6ca22af83bc447f74b1f475c9bd2e99ccef7347144572a9de5bcf5a5a21ad60100000000ffffffff013e3abc00000000001976a914cd5dc792f0abb0aa8ba4ca36c9fe5eda8e495ff988ac000000004e61bc00000000001976a91491b24bf9f5288532960ac687abb035127b1d28a588ac
all incoming transaction values validated
"""
    ),
    (
        "tx.py tx.bin KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn -o signed_tx.hex",
        'all incoming transaction values validated\n'
    ),
    (
        "tx.py -a signed_tx.hex",
        """\
Version:  1  tx hash 0995cf6f55e1cf22f7c31f5ad52d111e897b0b9b7e37a1bb755a470324b4a2c4  224 bytes   
TxIn count: 1; TxOut count: 1
Lock time: 0 (valid anytime)
Input:
  0: 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm from d61aa2a5f5bce59d2a57447134f7ce9ce9d29b5c471f4bf747c43bf82aa26c2a:1    123.45678 mBTC  sig ok
Output:
  0: 1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T receives    123.35678 mBTC
Total input     123.45678 mBTC
Total output    123.35678 mBTC
Total fees        0.10000 mBTC
01000000012a6ca22af83bc447f74b1f475c9bd2e99ccef7347144572a9de5bcf5a5a21ad6010000008b48304502210084fd73b302520381dea1885efda58bc446653998864db7a2cd04906fc6d5536302206325303c8e50f84d25c95eff2849441382d4aafb2f678f636a6d164b721bf0f101410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ffffffff013e3abc00000000001976a914cd5dc792f0abb0aa8ba4ca36c9fe5eda8e495ff988ac00000000
all incoming transaction values validated
"""
    )
]


class CmdTxTest(unittest.TestCase):
    def get_tempdir(self):
        return tempfile.mkdtemp()

    def launch_tool(self, tool_args, env={}):
        # set
        python_path = sys.executable
        script_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "pycoin", "scripts"))
        args = tool_args.split()
        script_path = os.path.join(script_dir, args[0])
        output = subprocess.check_output([python_path, script_path] + args[1:], env=env)
        return output.decode("utf8")

    def test_cases(self):
        cache_dir = tempfile.mkdtemp()
        os.chdir(cache_dir)
        env = dict(PYCOIN_CACHE_DIR=cache_dir)
        for cmd, expected_output in TEST_CASES:
            actual_output = self.launch_tool(cmd, env=env)
            if actual_output != expected_output:
                print(repr(cmd))
                print(repr(actual_output))
                print(repr(expected_output))
            self.assertEqual(expected_output, actual_output)


def main():
    unittest.main()

if __name__ == "__main__":
    main()
