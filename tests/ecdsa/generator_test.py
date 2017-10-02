import unittest

from pycoin.ecdsa.Point import Point
from pycoin.ecdsa.Generator import Generator
from pycoin.ecdsa.Curve import Curve


class GeneratorTestCase(unittest.TestCase):

    c23 = Curve(23, 1, 1)

    def do_test_add(self, c, x1, y1, x2, y2, x3, y3):
        """We expect that on curve c, (x1,y1) + (x2, y2) = (x3, y3)."""
        p1 = Point(x1, y1, c)
        p2 = Point(x2, y2, c)
        p3 = p1 + p2
        print("%s + %s = %s" % (p1, p2, p3))
        if p3[0] != x3 or p3[1] != y3:
            raise unittest.FailedTest("Failure: should give (%d,%d)." % (x3, y3))
        else:
            print(" Good.")

    def do_test_double(self, c, x1, y1, x3, y3):
        """We expect that on curve c, 2*(x1,y1) = (x3, y3)."""
        p1 = Point(x1, y1, c)
        p3 = p1 + p1
        print("%s doubled = %s" % (p1, p3))
        if p3[0] != x3 or p3[1] != y3:
            raise unittest.FailedTest("Failure: should give (%d,%d)." % (x3, y3))
        else:
            print(" Good.")

    def do_test_double_infinity(self, c):
        """We expect that on curve c, 2*INFINITY = INFINITY."""
        p1 = c._infinity
        p3 = p1 + p1
        print("%s doubled = %s" % (p1, p3))
        if p3[0] != p1[0] or p3[1] != p1[1]:
            raise unittest.FailedTest("Failure: should give (%d,%d)." % (p1[0], p1[1]))
        else:
            print(" Good.")

    def do_test_multiply(self, c, x1, y1, m, x3, y3):
        """We expect that on curve c, m*(x1,y1) = (x3,y3)."""
        p1 = Point(x1, y1, c)
        p3 = p1 * m
        print("%s * %d = %s" % (p1, m, p3))
        if p3[0] != x3 or p3[1] != y3:
            raise unittest.FailedTest("Failure: should give (%d,%d)." % (x3, y3))
        else:
            print(" Good.")

    def test_all(self):
        # A few tests from X9.62 B.3:

        self.do_test_add(self.c23, 3, 10, 9, 7, 17, 20)
        self.do_test_double(self.c23, 3, 10, 7, 12)
        self.do_test_add(self.c23, 3, 10, 3, 10, 7, 12)  # (Should just invoke double.)
        self.do_test_multiply(self.c23, 3, 10, 2, 7, 12)

        self.do_test_double_infinity(self.c23)

        # From X9.62 I.1 (p. 96):

        g = Point(13, 7, self.c23)

        check = self.c23._infinity
        for i in range(8):
            p = (i % 7) * g
            print("%s * %d = %s, expected %s . . ." % (g, i, p, check))
            self.assertEqual(p, check)
            check = check + g

        # NIST Curve P-192:
        p = 6277101735386680763835789423207666416083908700390324961279
        r = 6277101735386680763835789423176059013767194773182842284081
        #  s = 0x3045ae6fc8422f64ed579528d38120eae12196d5L
        #  c = 0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65
        b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
        Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
        Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811

        p192 = Generator(p, -3, b, (Gx, Gy), r)

        # Checking against some sample computations presented
        # in X9.62:

        d = 651056770906015076056810763456358567190100156695615665659
        Q = d * p192
        if Q[0] != 0x62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5:
            raise unittest.FailedTest("p192 * d came out wrong.")
        else:
            print("p192 * d came out right.")

        k = 6140507067065001063065065565667405560006161556565665656654
        R = k * p192
        if R[0] != 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD \
           or R[1] != 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835:
            raise unittest.FailedTest("k * p192 came out wrong.")
        else:
            print("k * p192 came out right.")

        u1 = 2563697409189434185194736134579731015366492496392189760599
        u2 = 6266643813348617967186477710235785849136406323338782220568
        temp = u1 * p192 + u2 * Q
        if temp[0] != 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEAD \
           or temp[1] != 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835:
            raise unittest.FailedTest("u1 * p192 + u2 * Q came out wrong.")
        else:
            print("u1 * p192 + u2 * Q came out right.")
