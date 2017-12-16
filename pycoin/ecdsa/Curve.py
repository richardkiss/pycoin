# Adapted from code written in 2005 by Peter Pearson and placed in the public domain.


from .Point import Point


def _leftmost_bit(x):
    # this is closer to constant time than bit-twiddling hacks like those in
    # https://graphics.stanford.edu/~seander/bithacks.html
    assert x > 0
    result = 1
    while result <= x:
        result <<= 1
    return result >> 1


class Curve(object):
    """
    Elliptic Curve over the field of integers modulo a prime.
    A curve is instantiated with a prime modulus p, and coefficients a and b.
    """
    def __init__(self, p, a, b, order=None):
        """The curve of points satisfying y^2 = x^3 + a*x + b (mod p)."""
        self._p = p
        self._a = a
        self._b = b
        self._order = order
        self._infinity = Point(None, None, self)

    def p(self):
        """The prime modulus of the curve."""
        return self._p

    def order(self):
        return self._order

    def infinity(self):
        """The "point at infinity" (also known as 0)."""
        return self._infinity

    def contains_point(self, x, y):
        """Is the point (x, y) on the curve?"""
        if x is None and y is None:
            return True
        return (y * y - (x * x * x + self._a * x + self._b)) % self._p == 0

    def add(self, p0, p1):
        """Add one point to another point."""
        p = self._p
        infinity = self._infinity

        if p0 == infinity:
            return p1
        if p1 == infinity:
            return p0

        x0, y0 = p0
        x1, y1 = p1
        if (x0 - x1) % p == 0:
            if (y0 + y1) % p == 0:
                return infinity
            else:
                slope = ((3 * x0 * x0 + self._a) * self.inverse_mod(2 * y0, p)) % p
        else:
            slope = ((y1 - y0) * self.inverse_mod(x1 - x0, p)) % p

        x3 = (slope * slope - x0 - x1) % p
        y3 = (slope * (x0 - x3) - y0) % p

        return self.Point(x3, y3)

    def multiply(self, p, e):
        """Multiply a point by an integer."""

        if self._order:
            e %= self._order
        if p == self._infinity or e == 0:
            return self._infinity

        e3 = 3 * e
        i = _leftmost_bit(e3) >> 1
        result = p
        while i > 1:
            result += result
            if (e3 & i):
                v = [result, result+p]
            else:
                v = [result-p, result]
            result = v[0 if (e & i) else 1]
            i >>= 1

        return result

    def inverse_mod(self, a, m):
        """Inverse of a mod m."""

        if a < 0 or m <= a:
            a = a % m

        # From Ferguson and Schneier, roughly:

        c, d = a, m
        uc, vc, ud, vd = 1, 0, 0, 1
        while c != 0:
            q, c, d = divmod(d, c) + (c,)
            uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc

        # At this point, d is the GCD, and ud*a+vd*m = d.
        # If d == 1, this means that ud is a inverse.

        assert d == 1
        if ud > 0:
            return ud
        else:
            return ud + m

    def Point(self, x, y):
        """
        The point constructor for this curve
        """
        return Point(x, y, self)

    def __repr__(self):
        return '{}({!r},{!r},{!r})'.format(self.__class__.__name__, self._p, self._a, self._b)

    def __str__(self):
        return 'y^2 = x^3 + {}*x + {} (mod {})'.format(self._a, self._b, self._p)
