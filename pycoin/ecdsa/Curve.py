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
    This class implements an `Elliptic curve <https://en.wikipedia.org/wiki/Elliptic_curve>`_ intended
    for use in `Elliptic curve cryptography <https://en.wikipedia.org/wiki/Elliptic-curve_cryptography>`_

    An elliptic curve ``EC<p, a, b>`` for a (usually large) prime p and integers a and b is a
    `group <https://en.wikipedia.org/wiki/Group_(mathematics)>`_. The members of the group are
    (x, y) points (where x and y are integers over the field of integers modulo p) that satisfy the relation
    ``y**2 = x**3 + a*x + b (mod p)``. There is a group operation ``+`` and an extra point known
    as the "point at infinity" thrown in to act as the identity for the group.

    The group operation is a truly marvelous property of this construct, a description of which
    this margin is too narrow to contain, so please refer to the links above for more information.

    :param p: a prime
    :param a: an integer coefficient
    :param b: an integer constant
    :param order: (optional) the order of the group made up by the points on the
        curve. Any point on the curve times the order is the identity for this
        group (the point at infinity). Although this is optional, it's required
        for some operations.
    """
    def __init__(self, p, a, b, order=None):
        """
        """
        self._p = p
        self._a = a
        self._b = b
        self._order = order
        self._infinity = Point(None, None, self)

    def p(self):
        """
        :returns: the prime modulus of the curve.
        """
        return self._p

    def order(self):
        """
        :returns: the order of the curve.
        """
        return self._order

    def infinity(self):
        """:returns: the "point at infinity" (also known as 0, or the identity)."""
        return self._infinity

    def contains_point(self, x, y):
        """
        :param x: x coordinate of a point
        :param y: y coordinate of a point
        :returns: True if the point (x, y) is on the curve, False otherwise
        """
        if x is None and y is None:
            return True
        return (y * y - (x * x * x + self._a * x + self._b)) % self._p == 0

    def add(self, p0, p1):
        """
        :param p0: a point
        :param p1: a point
        :returns: the sum of the two points
        """
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
        """
        multiply a point by an integer.

        :param p: a point
        :param e: an integer
        :returns: the result, equivalent to adding p to itself e times
        """

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
        """
        :param a: an integer
        :param m: another integer
        :returns: the value ``b`` such that ``a * b == 1 (mod m)``
        """

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
        :returns: a :class:`Point <.Point>` object with coordinates ``(x, y)``
        """
        return Point(x, y, self)

    def __repr__(self):
        return '{}({!r},{!r},{!r})'.format(self.__class__.__name__, self._p, self._a, self._b)

    def __str__(self):
        return 'y^2 = x^3 + {}*x + {} (mod {})'.format(self._a, self._b, self._p)
