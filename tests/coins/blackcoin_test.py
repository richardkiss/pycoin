#!/usr/bin/env python

import binascii
import io
import unittest

from pycoin.coins.blackcoin import Block
from pycoin.serialize import h2b, b2h

class BlackcoinTests(unittest.TestCase):

    def test_blackcoin(self):
        # Blackcoin block 114072, containing 2 txn
        block_114072_hash = 'f2580bd47b74df9739c1006fbae527348cd3a1bf720935d28a2b948e5a00f12e'
        block_114072_raw = h2b('06000000a0f137457cd0a39400aa39b1ea54c92f8de3683a37de9cd3759cc2bed342644662b7887fa9ca5bf2bc0db76cdc04c1bf7941410982f00cb038448e9360eb2074340f6953463f0a1d000000000201000000340f6953010000000000000000000000000000000000000000000000000000000000000000ffffffff040398bd01ffffffff010000000000000000000000000001000000340f6953017c8d38dc95d74fe617bcdc65f7765e624bd0a15258f232df7d9013d38f6798360200000049483045022100ffc35355837100fe11e81a68180b53b8c80b3973003eb874252c905e57c2a9a7022057df38b4264565c8c9ce292fa8eb3eca5dbcf65d0db593f7ab60223274843e0401ffffffff020000000000000000007429c592a10000002321039a9402f6eb37e3365fc124ab0f461a5a164132b027430d1b0340cb5e81a2c59eac00000000463044022013cb127935dd38b67bde928b250ac6c532c8f1f3d9d0ce88fe44899f93a3a1aa02203a7e69a2c033fbbbbef742fa63fb244f2c07098794a7b1de2b893d24f30b0b65')
        block_114072_sig = h2b('3044022013cb127935dd38b67bde928b250ac6c532c8f1f3d9d0ce88fe44899f93a3a1aa02203a7e69a2c033fbbbbef742fa63fb244f2c07098794a7b1de2b893d24f30b0b65')

        block = Block.parse(io.BytesIO(block_114072_raw))

        self.assertEqual(len(block.txs), 2)
        self.assertEqual(block.id(), block_114072_hash)
        self.assertEqual(block.signature, block_114072_sig)

        self.assertEqual(block.txs[0].id(),
                '834e501292983cfcc249a2f6693395ff1be1eddda8065e610fabad806d639601')
        self.assertEqual(block.txs[1].id(),
                'd3fe93274c49d30637ceb7b4033d7e7f42e82d75723b0268a646d6bb5495873a')

        # test special "mined time" value stored in Tx header
        # 1399394100 == "Tue May  6 12:35:00 2014"
        self.assertEqual(block.txs[0].mined_time, 1399394100)
        self.assertEqual(block.txs[1].mined_time, 1399394100)

        with io.BytesIO() as s:
            block.stream(s)
            regen = s.getvalue()
        self.assertEqual(block_114072_raw, regen)


if __name__ == "__main__":
    unittest.main()
