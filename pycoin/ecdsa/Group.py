from .Curve import Curve
from .Point import Point

from .numbertheory import modular_sqrt
from .rfc6979 import deterministic_generate_k


class Group(Curve, Point):
    def __new__(self, p, a, b, basis, order):
        return tuple.__new__(self, basis)

    def __init__(self, p, a, b, basis, order):
        Curve.__init__(self, p, a, b)
        Point.__init__(self, *basis, self)
        self._order = order

    def order(self):
        return self._order

    def public_pairs_for_x(self, x):
        y0, y1 = self.y_values_for_x(x)
        return (self.Point(x, y0), self.Point(x, y1))

    def public_pair_for_x(self, x, is_y_even):
        for p in self.public_pairs_for_x(x):
            if bool(is_y_even) == bool(p[1] & 1):
                return p

    def y_values_for_x(self, x):
        p = self._p
        alpha = (pow(x, 3, p) + self._a * x + self._b) % p
        beta = self.modular_sqrt(alpha)
        return (beta, p - beta)

    def modular_sqrt(self, a):
        return modular_sqrt(a, self._p)

    def inverse(self, a):
        return self.inverse_mod(a, self._order)

    def possible_public_pairs_for_signature(self, value, signature):
        r, s = signature
        mE = (-value % self._order) * self

        # recid = nV - 27
        # 1.1
        inv_r = self.inverse(r)
        for y in self.y_values_for_x(r):
            # 1.4 the constructor checks that nR is at infinity
            R = self.Point(r, y)
            # 1.6 compute Q = r^-1 (sR - eG)
            yield inv_r * (s * R + mE)

    def sign(self, secret_exponent, val, gen_k=deterministic_generate_k):
        n = self._order
        k = gen_k(n, secret_exponent, val)
        p1 = k * self
        r = p1[0]
        if r == 0:
            raise RuntimeError("amazingly unlucky random number r")
        s = (self.inverse(k) * (val + (secret_exponent * r) % n)) % n
        if s == 0:
            raise RuntimeError("amazingly unlucky random number s")
        return self.Point(r, s)

    def verify(self, public_pair, val, sig):
        """
        Verify that signature is a valid signature of hash.
        Return True if the signature is valid.
        """

        # From X9.62 J.3.1.

        n = self._order
        r, s = sig
        if r < 1 or r > n-1:
            return False
        if s < 1 or s > n-1:
            return False
        s_inverse = self.inverse(s)
        u1 = (val * s_inverse) % n
        u2 = (r * s_inverse) % n
        point = u1 * self + u2 * self.Point(*public_pair)
        v = point[0] % n
        return v == r
