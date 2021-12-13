import unittest

from pycoin.contrib.bech32m import bech32_decode, bech32_encode, decode, encode, Encoding
from pycoin.encoding.hexbytes import b2h


class Bech32Test(unittest.TestCase):
    def test_bip350_vectors(self):
        # from
        # https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
        # #Test_vectors_for_v0v16_native_segregated_witness_addresses

        VALID = """
            A1LQFN3A
            a1lqfn3a
            an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6
            abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx
            11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8
            split1checkupstagehandshakeupstreamerranterredcaperredlc445v
            ?1v759aa""".split()
        for _ in VALID:
            hrp, data, spec = bech32_decode(_)
            self.assertEqual(spec, Encoding.BECH32M)
            encoded = bech32_encode(hrp, data, spec)
            self.assertEqual(_.lower(), encoded)

        INVALID = [
            "\x201xj0phk", # : HRP character out of range
            "\x7f1g6xzxy", # : HRP character out of range
            "\x801vctc34", # : HRP character out of range
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", # : overall max length exceeded
            "qyrz8wqd2c9m", # : No separator character
            "1qyrz8wqd2c9m", # : Empty HRP
            "y1b0jsk6g", # : Invalid data character
            "lt1igcx5c0", # : Invalid data character
            "in1muywd", # : Too short checksum
            "mm1crxm3i", # : Invalid character in checksum
            "au1s5cgom", # : Invalid character in checksum
            "M1VUXWEZ", # : checksum calculated with uppercase form of HRP
            "16plkw9", # : empty HRP
            "1p2gdwpf", # : e
        ]
        for _ in INVALID:
            hrp, data, spec = bech32_decode(_)
            self.assertIsNone(hrp)
            self.assertIsNone(data)
            self.assertIsNone(spec)

        ADDRESSES = """BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4: 0014751e76e8199196d454941c45d1b3a323f1433bd6
            tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7: 00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262
            bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y: 5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6
            BC1SW50QGDZ25J: 6002751e
            bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs: 5210751e76e8199196d454941c45d1b3a323
            tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy: 0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433
            tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c: 5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433
            bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0: 512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"""

        for line in ADDRESSES.split("\n"):
            address, script_pub_key_hex = line.split(": ")
            address = address.strip()
            pos = address.rfind("1")
            hrp = address[:pos].lower()
            v = decode(hrp, address)
            version, blob = v
            if version != 0:
                version += 0x50
            calc_hex = b2h(bytearray([version] + [len(blob)] + blob))
            self.assertEqual(calc_hex, script_pub_key_hex)

        BAD_ADDRESSES = """tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut: Invalid human-readable part
            bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd: Invalid checksum (Bech32 instead of Bech32m)
            tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf: Invalid checksum (Bech32 instead of Bech32m)
            BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL: Invalid checksum (Bech32 instead of Bech32m)
            bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh: Invalid checksum (Bech32m instead of Bech32)
            tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47: Invalid checksum (Bech32m instead of Bech32)
            bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4: Invalid character in checksum
            BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R: Invalid witness version
            bc1pw5dgrnzv: Invalid program length (1 byte)
            bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav: Invalid program length (41 bytes)
            BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P: Invalid program length for witness version 0 (per BIP141)
            tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq: Mixed case
            bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf: zero padding of more than 4 bits
            tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j: Non-zero padding in 8-to-5 conversion
            bc1gmk9yu"""

        for line in BAD_ADDRESSES.split("\n"):
            address = line.split(": ")[0].strip()
            pos = address.rfind("1")
            hrp = address[:pos].lower()
            if hrp not in ["tb", "bc"]:
                continue
            v = decode(hrp, address)
            self.assertEqual(v, (None, None))
