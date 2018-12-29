import binascii
import unittest

from pycoin.bloomfilter import filter_size_required, hash_function_count_required, BloomFilter, murmur3
from pycoin.symbols.btc import network

Spendable = network.tx.Spendable

h2b = binascii.unhexlify


class BloomFilterTest(unittest.TestCase):

    def test_filter_size_required(self):
        for ec, fpp, ev in [
            (1, 0.00001, 3),
            (1, 0.00000001, 5),
            (100, 0.000001, 360),
        ]:
            fsr = filter_size_required(ec, fpp)
            self.assertEqual(fsr, ev)

    def test_hash_function_count_required(self):
        for fs, ec, ev in [
            (1, 1, 6),
            (3, 1, 17),
            (5, 1, 28),
            (360, 100, 20),
        ]:
            av = hash_function_count_required(fs, ec)
            self.assertEqual(av, ev)

    def test_BloomFilter(self):
        bf = BloomFilter(20, hash_function_count=5, tweak=127)
        bf.add_hash160(h2b("751e76e8199196d454941c45d1b3a323f1433bd6"))
        tx_hash = h2b("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        spendable = Spendable(coin_value=1000, script=b'foo', tx_hash=tx_hash, tx_out_index=1)
        bf.add_spendable(spendable)
        self.assertEqual(bf.filter_bytes, h2b("0000400000000008011130000000101100000000"))

    def test_murmur3(self):
        # test vectors from https://stackoverflow.com/questions/14747343/murmurhash3-test-vectors
        TEST_VECTORS = [
            (b'', 0, 0),
            (b'', 1, 0x514E28B7),
            (b'', 0xffffffff, 0x81F16F39),  # | make sure your seed uses unsigned 32-bit math
            (h2b("FFFFFFFF"), 0, 0x76293B50),  # | make sure 4-byte chunks use unsigned math
            (h2b("21436587"), 0, 0xF55B516B),  # | Endian order. UInt32 should end up as 0x87654321
            (h2b("21436587"), 0x5082EDEE, 0x2362F9DE),  # | Special seed value eliminates initial key with xor
            (h2b("214365"), 0, 0x7E4A8634),  # | Only three bytes. Should end up as 0x654321
            (h2b("2143"), 0, 0xA0F7B07A),  # | Only two bytes. Should end up as 0x4321
            (h2b("21"), 0, 0x72661CF4),  # | Only one byte. Should end up as 0x21
            (h2b("00000000"), 0, 0x2362F9DE),  # | Make sure compiler doesn't see zero and convert to null
            (h2b("000000"), 0, 0x85F0B427),  #
            (h2b("0000"), 0, 0x30F4C306),
            (h2b("00"), 0, 0x514E28B7),
        ]
        for data, seed, expected_value in TEST_VECTORS:
            actual_value = murmur3(data, seed=seed)
            self.assertEqual(expected_value, actual_value)


if __name__ == "__main__":
    unittest.main()
