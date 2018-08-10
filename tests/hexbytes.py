import unittest

from pycoin.encoding.hexbytes import h2b, h2b_rev, b2h, b2h_rev


class HexbytesTest(unittest.TestCase):

    def test_h2b(self):
        h = "000102"
        b = b"\x00\x01\x02"
        self.assertEqual(h2b(h), b)
        self.assertEqual(b2h(b), h)
        self.assertEqual(h2b_rev(h), b[::-1])
        self.assertEqual(b2h_rev(b), "020100")


if __name__ == '__main__':
    unittest.main()
