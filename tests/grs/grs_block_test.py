import io
import pytest
import unittest

from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.grs import network as GroestlcoinMainnet


pytest.importorskip('groestlcoin_hash')

# Block 2000000
BLOCK_HASH = '00000000000434d5b8d1c3308df7b6e3fd773657dfb28f5dd2f70854ef94cc66'


class GroestlcoinBlockTestCase(unittest.TestCase):
    def _get_block_stream(self):
        return io.BytesIO(h2b(
            "000000202c962905d18d95055e0b8d8f45ce748a44c119817058c23465b71100000000"
            "0077da86d33f0c2e51b3e2aa2ba24551141edd68a1cc890e083521361993c31932c4f7"
            "a65aecf5141baa90713202010000000001010000000000000000000000000000000000"
            "000000000000000000000000000000ffffffff4c0380841e04c4f7a65a08fabe6d6d33"
            "312d33302d383130325b6d36335b1b3691506e2a97a2c14df7e9bc6e94e54001000000"
            "0000000060000413010200000d2f6e6f64655374726174756d2f000000000200000000"
            "00000000266a24aa21a9ed8dfe2e8f6eb7ff2d6e27732d11c6aaee5eab7d5ea67b6cf8"
            "87ec9d4cd038e831a876cd1d000000001976a91442bbcfb1cd88dbbb4c56086f1d018f"
            "10a7ef760688ac01200000000000000000000000000000000000000000000000000000"
            "000000000000000000000100000001f7b346fc08b41de682b81b7ce729edb2aeddc2f5"
            "87b759859031e3bf99e68779000000006b483045022100e00b07400fbe10ee93962425"
            "57026ff6d3e16ffb46add2ccc5d7ffd8ddbc1989022003cc6832c4d62e154781507488"
            "67ca71eca04655f4b2ce31773832353d571647012102d4ad38a64b4ec115a77a900d6f"
            "b7f44343aa761ab6fcf8b8613443fa7e24e5befeffffff026e539827000000001976a9"
            "145db12e800001e767f56a3dbb202d0666315d063288acb5162400000000001976a914"
            "bd7b0274f1ef4325d0e8e273ed5be328bc3d11d988ac4a841e00"))

    def test_block_hash(self):
        parsed = GroestlcoinMainnet.block.parse(self._get_block_stream())
        self.assertEqual(str(parsed.hash()), BLOCK_HASH)

    def test_block_data(self):
        parsed = GroestlcoinMainnet.block.parse(self._get_block_stream())
        self.assertEqual(parsed.version, 536870912)
        self.assertEqual(str(parsed.previous_block_hash),
                         '000000000011b76534c258708119c1448a74ce458f8d0b5e05958dd10529962c')
        self.assertEqual(str(parsed.merkle_root),
                         '3219c39319362135080e89cca168dd1e145145a22baae2b3512e0c3fd386da77')
        self.assertEqual(parsed.timestamp, 1520891844)
        self.assertEqual(parsed.difficulty, int('1b14f5ec', 16))
        self.assertEqual(parsed.nonce, 846303402)

    def test_block_txs(self):
        parsed = GroestlcoinMainnet.block.parse(self._get_block_stream())
        tx = parsed.txs[0]
        self.assertEqual(str(tx.hash()), '7a64cd89b9e0fd6b32be5deb349e460a90e6805278dee2fe301b347623f0806b')
        self.assertTrue(tx.is_coinbase())

        tx = parsed.txs[1]
        self.assertEqual(str(tx.hash()), '89ff39e83636359bace69725fe19e1d33b16918205eaaf77c37684ac557e5154')
        self.assertEqual(tx.txs_out[0].coin_value, 664294254)
        self.assertEqual(GroestlcoinMainnet.address.for_script(tx.txs_out[0].puzzle_script()),
                         'Fdi7YYeN7nmnjJPqQDGy8vudgQ26FVjNrk')
        self.assertEqual(tx.txs_out[1].coin_value, 2365109)
        self.assertEqual(GroestlcoinMainnet.address.for_script(tx.txs_out[1].puzzle_script()),
                         'FnSbX2G6VkrCqCLBFPxwbrC9xT7C3rh5ko')
