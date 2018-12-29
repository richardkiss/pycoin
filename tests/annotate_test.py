import unittest

from pycoin.networks.registry import network_for_netcode


def make_tests_for_netcode(netcode):
    network = network_for_netcode(netcode)

    Tx = network.tx
    annotate_scripts = network.annotate.annotate_scripts

    class DisassembleTest(unittest.TestCase):

        def test_validate(self):
            input_tx = Tx.from_hex(
                "01000000019c97afdf6c9a31ffa86d71ea79a079001e2b59ee408fd418498219400639ac0a01"
                "0000008b4830450220363cffae09599397b21e6d8a8073fb1dfbe06b6acdd0f2f7d3fea86ca9"
                "c3f605022100fa255a6ed23fd825c759ef1a885a31cad0989606ca8a3a16657d50fe3cef5828"
                "014104ff444bac08308b9ec97f56a652ad8866e0ba804da97868909999566cb377f4a2c8f100"
                "0e83b496868f3a282e1a34df78565b65c15c3fa21a0763fd81a3dfbbb6ffffffff02c05eecde"
                "010000001976a914588554e6cc64e7343d77117da7e01357a6111b7988ac404b4c0000000000"
                "1976a914ca6eb218592f289999f13916ee32829ad587dbc588ac00000000")
            tx_to_validate = Tx.from_hex(
                "010000000165148d894d3922ef5ffda962be26016635c933d470c8b0ab7618e869e3f70e3c00"
                "0000008b48304502207f5779ebf4834feaeff4d250898324eb5c0833b16d7af4c1cb0f66f50f"
                "cf6e85022100b78a65377fd018281e77285efc31e5b9ba7cb7e20e015cf6b7fa3e4a466dd195"
                "014104072ad79e0aa38c05fa33dd185f84c17f611e58a8658ce996d8b04395b99c7be36529ca"
                "b7606900a0cd5a7aebc6b233ea8e0fe60943054c63620e05e5b85f0426ffffffff02404b4c00"
                "000000001976a914d4caa8447532ca8ee4c80a1ae1d230a01e22bfdb88ac8013a0de01000000"
                "1976a9149661a79ae1f6d487af3420c13e649d6df3747fc288ac00000000")
            tx_db = {tx.hash(): tx for tx in [input_tx]}
            tx_to_validate.unspents_from_db(tx_db)
            self.assertEqual("OP_DUP OP_HASH160 [d4caa8447532ca8ee4c80a1ae1d230a01e22bfdb] OP_EQUALVERIFY OP_CHECKSIG",
                             network.script.disassemble(tx_to_validate.txs_out[0].script))
            self.assertEqual(tx_to_validate.id(), "7c4f5385050c18aa8df2ba50da566bbab68635999cc99b75124863da1594195b")
            annotate_scripts(tx_to_validate, 0)

        def test_disassemble(self):
            input_tx = Tx.from_hex(
                "01000000010000000000000000000000000000000000000000000000000000000000000000"
                "ffffffff0704ffff001d0134ffffffff0100f2052a0100000043410411db93e1dcdb8a016b"
                "49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e16"
                "0bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000")
            tx_db = {tx.hash(): tx for tx in [input_tx]}
            tx_to_validate = Tx.from_hex(
                "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402"
                "204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4"
                "acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b"
                "13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1ba"
                "ded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482e"
                "cad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000")
            tx_to_validate.unspents_from_db(tx_db)
            self.assertEqual(tx_to_validate.id(), "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
            r = annotate_scripts(tx_to_validate, 0)
            EXPECTED = [
                (
                    ['--- SIGNATURE SCRIPT START'], 0, 0x47,
                    ('[PUSH_71] 304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220'
                     '181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901'),
                    [
                        'r: 0x4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41',
                        's: 0x181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09',
                        'z: 0x7a05c6145f10101e9d6325494245adf1297d80f8f38d4d576d57cdba220bcb19',
                        'signature type SIGHASH_ALL',
                        (' sig for 1M6HTkQf7RhsrDLDX7Q6GJkxXbTz8VWxMx 1E5CDVQrLjSqTeqfN5zT2X2DoeYS7od2Mi '
                         '13KiMqUJ7xD6MhUD2k7mKEoZMHDP9HdWwW 12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S')
                    ]
                ),
                (
                    ['--- PUBLIC KEY SCRIPT START'], 0, 0x41,
                    ('[PUSH_65] 0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0ead'
                     'dfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3'),
                    ['SEC for uncompressed 12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S']
                ),
                ([], 0x42, 0xac, 'OP_CHECKSIG', [])]
            self.assertEqual(r, EXPECTED)

    return DisassembleTest


for netcode in ["BTC"]:
    exec("%sTests = make_tests_for_netcode('%s')" % (netcode, netcode))


if __name__ == "__main__":
    unittest.main()
