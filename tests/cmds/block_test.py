import unittest
import tempfile

from pycoin.encoding.hexbytes import h2b

from .ToolTest import ToolTest


class BlockTest(ToolTest):

    def test_block_dump(self):
        block_hex = (
            '01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a000000'
            '0044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe'
            '6649ffff001d05e0ed6d01010000000100000000000000000000000000000000000000'
            '00000000000000000000000000ffffffff0704ffff001d010effffffff0100f2052a01'
            '00000043410494b9d3e76c5b1629ecf97fff95d7a4bbdac87cc26099ada28066c6ff1e'
            'b9191223cd897194a08d0c2726c5747f1db49e8cf90e75dc3e3550ae9b30086f3cd5aa'
            'ac00000000')
        block_bin = h2b(block_hex)
        block_file = tempfile.NamedTemporaryFile()
        block_file.write(block_bin)
        block_file.flush()
        output = self.launch_tool("block %s" % block_file.name)
        self.assertEqual(output, """215 bytes   block hash 0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449
version 1
prior block hash 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
merkle root 44f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e99
timestamp 2009-01-09T03:02:53
difficulty 486604799
nonce 1844305925
1 transaction
Tx #0:
Version:  1  tx hash 999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644  134 bytes
TxIn count: 1; TxOut count: 1
Lock time: 0 (valid anytime)
Input:
   0: COINBASE   50000.00000 mBTC
Output:
   0: 1FvzCLoTPGANNjWoUo6jUGuAG3wg1w4YjR receives  50000.00000 mBTC
Total input   50000.00000 mBTC
Total output  50000.00000 mBTC
Total fees        0.00000 mBTC

""")


def main():
    unittest.main()


if __name__ == "__main__":
    main()
