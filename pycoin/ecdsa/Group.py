from .Curve import Curve
from .Point import Point

from .numbertheory import modular_sqrt
from .rfc6979 import deterministic_generate_k


class Group(Curve, Point):
    def __new__(self, p, a, b, basis, order):
        return tuple.__new__(self, basis)

    def __init__(self, p, a, b, basis, order):
        Curve.__init__(self, p, a, b)
        Point.__init__(self, basis[0], basis[1], self)
        self._order = order
        self._powers = []
        Gp = self
        for _ in range(256):
            self._powers.append(Gp)
            Gp += Gp

    def order(self):
        return self._order

    def modular_sqrt(self, a):
        return modular_sqrt(a, self._p)

    def inverse(self, a):
        return self.inverse_mod(a, self._order)

    def y_values_for_x(self, x, y_parity=None):
        p = self._p
        alpha = (pow(x, 3, p) + self._a * x + self._b) % p
        beta = self.modular_sqrt(alpha)
        if y_parity is None:
            return (beta, p - beta)
        if beta & 1 == y_parity:
            return [beta]
        return [p - beta]

    def public_pairs_for_x(self, x, y_parity=None):
        return [self.Point(x, y) for y in self.y_values_for_x(x, y_parity=y_parity)]

    def public_pair_for_x(self, x, is_even):
        y = self.y_values_for_x(x, y_parity=1 ^ is_even)[0]
        return self.Point(x, y)

    def possible_public_pairs_for_signature(self, value, signature, y_parity=None):
        # y_parity is None, 0 or 1
        r, s = signature

        # recid = nV - 27
        # 1.1
        inv_r = self.inverse(r)
        minus_e = -value % self._order
        x = r
        l = []
        for y in self.y_values_for_x(x, y_parity=y_parity):
            # 1.4 the constructor checks that nR is at infinity
            R = self.Point(x, y)
            R.check_on_curve()
            # 1.6 compute Q = r^-1 (sR - eG)
            Q = inv_r * (s * R + minus_e * self)
            # check that Q is the public key
            l.append(Q)
        return l

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

    def __mul__(self, e):
        """Multiply a point by an integer."""
        P = self._infinity
        for _ in range(256):
            a = [P, P + self._powers[_]]
            P = a[e & 1]
            e >>= 1
        return P

    def __rmul__(self, other):
        """Multiply a point by an integer."""
        return self * other
