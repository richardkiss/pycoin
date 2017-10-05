
import binascii
import unittest

from pycoin.satoshi import stackops


def b2h(b):
    return binascii.hexlify(b).decode("utf8")


class StackOpsTest(unittest.TestCase):
    def test_do_OP_2DROP(self):
        s = [1, 2, 3]
        stackops.do_OP_2DROP(s)
        self.assertEqual(s, [1])

    def test_do_OP_2DUP(self):
        s = [1, 2]
        stackops.do_OP_2DUP(s)
        self.assertEqual(s, [1, 2, 1, 2])

    def test_do_OP_3DUP(self):
        s = [1, 2, 3]
        stackops.do_OP_3DUP(s)
        self.assertEqual(s, [1, 2, 3, 1, 2, 3])

    def test_do_OP_2OVER(self):
        s = [1, 2, 3, 4]
        stackops.do_OP_2OVER(s)
        self.assertEqual(s, [1, 2, 3, 4, 1, 2])

    def test_do_OP_2ROT(self):
        s = [1, 2, 3, 4, 5, 6]
        stackops.do_OP_2ROT(s)
        self.assertEqual(s, [3, 4, 5, 6, 1, 2])

    def test_do_OP_2SWAP(self):
        s = [1, 2, 3, 4]
        stackops.do_OP_2SWAP(s)
        self.assertEqual(s, [3, 4, 1, 2])

    def test_do_OP_IFDUP(self):
        s = [1, 2]
        stackops.do_OP_IFDUP(s)
        self.assertEqual(s, [1, 2, 2])
        s = [1, 2, 0]
        stackops.do_OP_IFDUP(s)
        self.assertEqual(s, [1, 2, 0])

    def test_do_OP_DROP(self):
        s = [1, 2]
        stackops.do_OP_DROP(s)
        self.assertEqual(s, [1])

    def test_do_OP_DUP(self):
        s = [1, 2]
        stackops.do_OP_DUP(s)
        self.assertEqual(s, [1, 2, 2])

    def test_do_OP_NIP(self):
        s = [1, 2]
        stackops.do_OP_NIP(s)
        self.assertEqual(s, [2])

    def test_do_OP_OVER(self):
        s = [1, 2]
        stackops.do_OP_OVER(s)
        self.assertEqual(s, [1, 2, 1])

    def test_do_OP_ROT(self):
        s = [1, 2, 3]
        stackops.do_OP_ROT(s)
        self.assertEqual(s, [2, 3, 1])

    def test_do_OP_SWAP(self):
        s = [1, 2, 3]
        stackops.do_OP_SWAP(s)
        self.assertEqual(s, [1, 3, 2])

    def test_do_OP_TUCK(self):
        s = [1, 2, 3]
        stackops.do_OP_TUCK(s)
        self.assertEqual(s, [1, 3, 2, 3])

    def test_do_OP_CAT(self):
        s = ["foo", "bar"]
        stackops.do_OP_CAT(s)
        self.assertEqual(s, ['foobar'])

    def test_do_OP_RIPEMD160(self):
        s = [b'foo']
        stackops.do_OP_RIPEMD160(s)
        self.assertEqual(len(s), 1)
        self.assertEqual(b2h(s[0]), "42cfa211018ea492fdee45ac637b7972a0ad6873")

    def test_do_OP_SHA1(self):
        s = [b'foo']
        stackops.do_OP_SHA1(s)
        self.assertEqual(len(s), 1)
        self.assertEqual(b2h(s[0]), "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33")

    def test_do_OP_SHA256(self):
        s = [b'foo']
        stackops.do_OP_SHA256(s)
        self.assertEqual(len(s), 1)
        self.assertEqual(b2h(s[0]), "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")

    def test_do_OP_HASH160(self):
        s = [b'foo']
        stackops.do_OP_HASH160(s)
        self.assertEqual(len(s), 1)
        self.assertEqual(b2h(s[0]), "e1cf7c8103476b6d7fe9e4979aa10e7c531fcf42")

    def test_do_OP_HASH256(self):
        s = [b'foo']
        stackops.do_OP_HASH256(s)
        self.assertEqual(len(s), 1)
        self.assertEqual(b2h(s[0]), "c7ade88fc7a21498a6a5e5c385e1f68bed822b72aa63c4a9a48a02c2466ee29e")


if __name__ == "__main__":
    unittest.main()
