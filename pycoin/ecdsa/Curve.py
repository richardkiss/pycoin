
#
# Implementation of elliptic curves, for cryptographic applications.
#
# This module doesn't provide any way to choose a random elliptic
# curve, nor to verify that an elliptic curve was chosen randomly,
# because one can simply use NIST's standard curves.
#
# Notes from X9.62-1998 (draft):
#   Nomenclature:
#     - Q is a public key.
#     The "Elliptic Curve Domain Parameters" include:
#     - q is the "field size", which in our case equals p.
#     - p is a big prime.
#     - G is a point of prime order (5.1.1.1).
#     - n is the order of G (5.1.1.1).
#   Public-key validation (5.2.2):
#     - Verify that Q is not the point at infinity.
#     - Verify that X_Q and Y_Q are in [0,p-1].
#     - Verify that Q is on the curve.
#     - Verify that nQ is the point at infinity.
#   Signature generation (5.3):
#     - Pick random k from [1,n-1].
#   Signature checking (5.4.2):
#     - Verify that r and s are in [1,n-1].
#
# Version of 2008.11.25.
#
# Revision history:
#    2005.12.31 - Initial version.
#    2008.11.25 - Change CurveFp.is_on to contains_point.
#
# Written in 2005 by Peter Pearson and placed in the public domain.


from .Point import Point
from .numbertheory import inverse_mod


class Curve(object):

    """Elliptic Curve over the field of integers modulo a prime."""
    def __init__(self, p, a, b):
        """The curve of points satisfying y^2 = x^3 + a*x + b (mod p)."""
        self._p = p
        self._a = a
        self._b = b
        self._infinity = Point(None, None, self)

    def p(self):
        return self._p

    def infinity(self):
        return self._infinity

    def check_point(self, p):
        """Is the point (x, y) on this curve?"""
        return self.contains_point(*p)

    def contains_point(self, x, y):
        """Is the point (x, y) on this curve?"""
        if x is None and y is None:
            return True
        return (y * y - (x * x * x + self._a * x + self._b)) % self._p == 0

    def add(self, p0, p1):
        """Add one point to another point."""

        # X9.62 B.3:

        if p0 == self._infinity:
            return p1
        if p1 == self._infinity:
            return p0

        x0, y0 = p0
        x1, y1 = p1
        if x0 == x1:
            if (y0 + y1) % self._p == 0:
                return self._infinity
            else:
                return self.double(p0)

        p = self._p

        l = ((y1 - y0) * self.inverse_mod(x1 - x0, p)) % p

        x3 = (l * l - x0 - x1) % p
        y3 = (l * (x0 - x3) - y0) % p

        return self.Point(x3, y3)

    def multiply(self, p, e):
        """Multiply a point by an integer."""

        def leftmost_bit(x):
            assert x > 0
            result = 1
            while result <= x:
                result = 2 * result
            return result // 2

        # From X9.62 D.3.2:

        if e == 0 or self == self._infinity:
            return self._infinity
        e3 = 3 * e
        negative_p = self.Point(p[0], -p[1])
        i = leftmost_bit(e3) // 2
        result = p
        while i > 1:
            result = self.double(result)
            if (e3 & i) != 0 and (e & i) == 0:
                result = result + p
            if (e3 & i) == 0 and (e & i) != 0:
                result = result + negative_p
            # print ". . . i = %d, result = %s" % (i, result)
            i = i // 2

        return result

    def double(self, p):
        """Return a new point that is twice the old."""

        if p == self._infinity:
            return self._infinity

        # X9.62 B.3:
        x, y = p
        l = ((3*x*x+self._a) * self.inverse_mod(2 * y, self._p)) % self._p

        x3 = (l * l-2 * x) % self._p
        y3 = (l * (x-x3) - y) % self._p

        return self.Point(x3, y3)

    def inverse_mod(self, a, p):
        return inverse_mod(a, p)

    def Point(self, x, y):
        return Point(x, y, self)

    def __repr__(self):
        return '{}({!r},{!r},{!r})'.format(self.__class__.__name__, self._p, self._a, self._b)

    def __str__(self):
        return 'y^2 = x^3 + {}*x + {} (mod {})'.format(self._a, self._b, self._p)
