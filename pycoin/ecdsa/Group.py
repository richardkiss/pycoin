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

    def public_pair_for_x(self, x, is_even):
        p = self._p
        alpha = (pow(x, 3, p) + self._a * x + self._b) % p
        beta = self.modular_sqrt(alpha)
        if bool(is_even) == bool(beta & 1):
            return (x, p - beta)
        return (x, beta)

    def modular_sqrt(self, a):
        return modular_sqrt(a, self._p)

    def inverse(self, a):
        return self.inverse_mod(a, self._order)

    def possible_public_pairs_for_signature(self, value, signature):
        p = self._p

        r, s = signature

        # recid = nV - 27
        # 1.1
        inv_r = self.inverse(r)
        minus_e = -value % self._order
        x = r
        # 1.3
        alpha = (pow(x, 3, p) + self._a * x + self._b) % p
        beta = self.modular_sqrt(alpha)
        for y in [beta, p - beta]:
            # 1.4 the constructor checks that nR is at infinity
            R = self.Point(x, y)
            # 1.6 compute Q = r^-1 (sR - eG)
            Q = inv_r * (s * R + minus_e * self)
            # check that Q is the public key
            if self.verify(Q, value, signature):
                # check that we get the original signing address
                yield Q

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
        point = u1 * self + u2 * self.Point(public_pair[0], public_pair[1])
        v = point[0] % n
        return v == r
