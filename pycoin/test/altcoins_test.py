#!/usr/bin/env python

import binascii
import io
import unittest

from pycoin.block import BlackcoinBlock, LitecoinBlock
from pycoin.serialize import h2b, b2h

class AltcoinsTests(unittest.TestCase):

    def test_blackcoin(self):
        # Blackcoin block 114072, containing 2 txn. May 6th, 2014
        block_114072_hash = 'f2580bd47b74df9739c1006fbae527348cd3a1bf720935d28a2b948e5a00f12e'
        block_114072_raw = h2b('06000000a0f137457cd0a39400aa39b1ea54c92f8de3683a37de9cd3759cc2bed342644662b7887fa9ca5bf2bc0db76cdc04c1bf7941410982f00cb038448e9360eb2074340f6953463f0a1d000000000201000000340f6953010000000000000000000000000000000000000000000000000000000000000000ffffffff040398bd01ffffffff010000000000000000000000000001000000340f6953017c8d38dc95d74fe617bcdc65f7765e624bd0a15258f232df7d9013d38f6798360200000049483045022100ffc35355837100fe11e81a68180b53b8c80b3973003eb874252c905e57c2a9a7022057df38b4264565c8c9ce292fa8eb3eca5dbcf65d0db593f7ab60223274843e0401ffffffff020000000000000000007429c592a10000002321039a9402f6eb37e3365fc124ab0f461a5a164132b027430d1b0340cb5e81a2c59eac00000000463044022013cb127935dd38b67bde928b250ac6c532c8f1f3d9d0ce88fe44899f93a3a1aa02203a7e69a2c033fbbbbef742fa63fb244f2c07098794a7b1de2b893d24f30b0b65')
        block_114072_sig = h2b('3044022013cb127935dd38b67bde928b250ac6c532c8f1f3d9d0ce88fe44899f93a3a1aa02203a7e69a2c033fbbbbef742fa63fb244f2c07098794a7b1de2b893d24f30b0b65')

        blk = BlackcoinBlock.parse(io.BytesIO(block_114072_raw))

        self.assertEqual(len(blk.txs), 2)
        self.assertEqual(blk.netcode, 'BLK')
        self.assertEqual(blk.id(), block_114072_hash)
        self.assertEqual(blk.block_sig, block_114072_sig)

        self.assertEqual(blk.txs[0].id(),
                '834e501292983cfcc249a2f6693395ff1be1eddda8065e610fabad806d639601')
        self.assertEqual(blk.txs[1].id(),
                'd3fe93274c49d30637ceb7b4033d7e7f42e82d75723b0268a646d6bb5495873a')
        self.assertEqual(blk.txs[0].netcode, 'BLK')

        # test special "mined time" value stored in Tx header
        # 1399394100 == "Tue May  6 12:35:00 2014"
        self.assertEqual(blk.txs[0].mined_time, 1399394100)
        self.assertEqual(blk.txs[1].mined_time, 1399394100)

        with io.BytesIO() as s:
            blk.stream(s)
            regen = s.getvalue()
        self.assertEqual(block_114072_raw, regen)

        with self.assertRaises(NotImplementedError):
            blk.block_sig = None
            with io.BytesIO() as s:
                blk.stream(s)

    def test_litecoin(self):
        # Litecoin block #562399  http://ltc.blockr.io/block/info/562399
        # just 3 txn! 
        b_hash = 'e8cfa021a51d33dcfdfa7e9aeb9f5a00aa42e86d8ea0cb3479319f773e1f4eb5'
        b_raw = h2b('020000000c724ece8d59a630efddf53311ed508a1db828ec00973194c4ec4367e6298baec468a155a4c8a64b737216f603e2a49ee49ff991da40f5dd93cc538b7ec94f74fe17695337ee081ba684b5290301000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2303df9408062f503253482f04e6176953080802ed8c24000000092f7374726174756d2f000000000100f2052a010000001976a914eda916237d9d8b46baa76f697b6c9343e45ed2de88ac0000000001000000019f1045512c0b48f7ea54c4895f34051d1ff47362033ada7603b7f7363cad7e87010000006b4830450221009b8f7f5d51d01c565bed36b0d821643cec3cdacf64525f0db92a5a3f898283cb02206471601caa83d156c823057ef66406b6e16c4566210b3dc95651780c00a3b39401210245c3a34148870dc9a7803c698d21dd6532d82626d78d16d40158763c3a566f16ffffffff01be952aa0010000001976a914cf13eb08302b6f55d6ba99654de132ad3b67ab2e88ac000000000100000002abc1249f7f4258c1593b7da45248469292ac99f185585b8391f68746e7abfaa6010000006b483045022100809af5f0a51c188b3b0a13f9da03393efd77249c2d633b4638f1d26c0c7d0a69022007d1fb113e8c7a95f4ebe2fc30fa91f413bdb3c13cff44b7adb6ba3c4dde6c83012102da69e08e7fc11f6bee0286ff0e8114ee8120a55c47719fa2a07951097a2db7b3ffffffff51a1cd456513e04c55dbffeed86ff7c1a312302897b0ec67aaab49ba25f26f45010000006b48304502207f15f1e0b71c0cc6c35194d8cd83502e42fec045cde074ea34d244112ec65187022100a551d30472eda95e58beafb60d35c77d3047e8a1942d7dda6aec4312888afc0d0121026ea3a12ea83231142ebc825243c141ecd7c267116d84dacc08907c6d067a525affffffff01dae8cf15000000001976a9142a546e72b7d844b098427ce750c21addf62a50bd88ac00000000')

        blk = LitecoinBlock.parse(io.BytesIO(b_raw))

        self.assertEqual(len(blk.txs), 3)
        self.assertEqual(blk.netcode, 'LTC')
        self.assertEqual(blk.id(), b_hash)

        self.assertEqual(blk.txs[0].netcode, 'LTC')

        for i, hh in enumerate((
                    'a8b631ddbcd1b4744cd355b02036ecf8208150177b7a5d2ef44a122949c402e3',
                    '0661d8bdd79137a888292430961c5e614d8bfb775a6693f18ac7f5b6392c0e9f',
                    '7ab578695dc354898ce1fc5e27110444b6802e5141f0b555b4e4e2576679c0aa')):
            self.assertEqual(blk.txs[i].id(), hh)


if __name__ == "__main__":
    unittest.main()
