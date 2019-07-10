import os

from .intstream import from_bytes

from .Curve import Curve
from .Point import Point

from .rfc6979 import deterministic_generate_k


class Generator(Curve, Point):
    """
    A Generator is a specific point on an elliptic curve that defines a `trapdoor
    function <https://en.wikipedia.org/wiki/Trapdoor_function>`_ from integers to curve points.

    :param p: the prime for the :class:`Curve <pycoin.ecdsa.Curve.Curve>`
    :param a: the a value for the :class:`Curve <pycoin.ecdsa.Curve.Curve>`
    :param b: the b value for the :class:`Curve <pycoin.ecdsa.Curve.Curve>`
    :param basis: a :class:`Point <pycoin.ecdsa.Point.Point>` on the
        given :class:`Curve <pycoin.ecdsa.Curve.Curve>`
    :param order: the order for the :class:`Curve <pycoin.ecdsa.Curve.Curve>`

    The constructor raises :class:`NoSuchPointError` if the point is invalid.
    The point at infinity is ``(x, y) == (None, None)``.
    """
    def __new__(self, p, a, b, basis, order):
        # since Generator extends tuple (via Point), we need to override __new__
        return tuple.__new__(self, basis)

    def __init__(self, p, a, b, basis, order, entropy_f=os.urandom):
        """
        Set up a group with generator basis for the curve y^2 = x^3 + x*a + b (mod p).
        The order is the order of the group (it's generally predetermined for a given curve;
        how it's calculated is complicated).
        The entropy function creates a blinding factor, to mitigate side channel attacks.
        """
        Curve.__init__(self, p, a, b, order)
        Point.__init__(self, basis[0], basis[1], self)
        self._powers = []
        Gp = self
        for _ in range(256):
            self._powers.append(Gp)
            Gp += Gp
        assert p % 4 == 3, "p % 4 must be 3 due to modular_sqrt optimization"
        self._mod_sqrt_power = (p + 1) // 4
        self._blinding_factor = from_bytes(entropy_f(32)) % self._order
        self._minus_blinding_factor_g = self.raw_mul(-self._blinding_factor)

    def modular_sqrt(self, a):
        """
        :return: n where ``n * n == a (mod p) for the curve's prime p``.
            If no such n exists, an arbitrary value will be returned.
        """
        return pow(a, self._mod_sqrt_power, self._p)

    def inverse(self, a):
        ":return: n where ``a * n == 1 (mod p) for the curve's prime p``."
        return self.inverse_mod(a, self._order)

    def points_for_x(self, x):
        """
        :param: x: an integer x coordinate
        :return: (p0, p1) where each p is a :class:`Point` with given x coordinate,
            and p0's y value is even.

        To get a point with particular parity, use::
            points_for_x(x)[1 if is_y_supposed_to_be_odd else 0]
        """
        p = self._p
        alpha = (pow(x, 3, p) + self._a * x + self._b) % p
        y0 = self.modular_sqrt(alpha)
        if y0 == 0:
            raise ValueError("no y value for %d" % x)
        p0, p1 = [self.Point(x, _) for _ in (y0, p - y0)]
        if y0 & 1 == 0:
            return (p0, p1)
        return (p1, p0)

    def possible_public_pairs_for_signature(self, value, signature, y_parity=None):
        """
        :param: value: an integer value
        :param: signature: an ``(r, s)`` pair of integers representing an ecdsa signature of ``value``
        :param: y_parity: (optional) for a given value and signature, there are either two points
            that sign it, or none if the signature is invalid. One of the points has an even y
            value, the other an odd. If this parameter is set, only points whose y value matches
            this value will be returned in the list.

        :return: a list of :class:`Point <pycoin.ecdsa.Point.Point>` objects p where each p is
            a possible public key for which ``signature`` correctly signs the given ``value``.
            If something goes wrong, this list will be empty.
        """
        r, s = signature

        try:
            points = self.points_for_x(r)
        except ValueError:
            return []

        if y_parity is not None:
            if y_parity & 1:
                points = points[1:]
            else:
                points = points[:1]

        inv_r = self.inverse(r)
        s_over_r = s * inv_r
        minus_E_over_r = -(inv_r * value) * self
        try:
            return [s_over_r * p + minus_E_over_r for p in points]
        except ValueError:
            return []

    def raw_mul(self, e):
        """
        :param: e: an integer value
        :returns: e * self

        This method uses a precomputed table as an optimization.
        """
        e %= self._order
        P = self._infinity
        for bit in range(256):
            # add the power of the generator every time to make it more time-deterministic
            a = [P, P + self._powers[bit]]
            # choose the correct result
            P = a[e & 1]
            e >>= 1
        return P

    def __mul__(self, e):
        """Multiply the generator by an integer. Uses the blinding factor."""
        return self.raw_mul(e + self._blinding_factor) + self._minus_blinding_factor_g

    def __rmul__(self, e):
        """Multiply the generator by an integer."""
        return self.__mul__(e)

    def verify(self, public_pair, val, sig):
        """
        :param: public_pair: a :class:`Point <pycoin.ecdsa.Point.Point>` on the curve
        :param: val: an integer value
        :param: sig: a pair of integers ``(r, s)`` representing an ecdsa signature

        :returns: True if and only if the signature ``sig`` is a valid signature
            of ``val`` using ``public_pair`` public key.
        """
        order = self._order
        if val == 0:
            return False
        r, s = sig
        if r < 1 or r >= order or s < 1 or s >= order:
            return False
        s_inverse = self.inverse(s)
        u1 = val * s_inverse
        u2 = r * s_inverse
        point = u1 * self + u2 * self.Point(*public_pair)
        v = point[0] % order
        return v == r

    def sign_with_recid(self, secret_exponent, val, gen_k=None):
        """
        :param: secret_exponent: a :class:`Point <pycoin.ecdsa.Point.Point>` on the curve
        :param: val: an integer value
        :param: gen_k: a function generating __k values__

        :returns: a tuple of integers ``(r, s, recid)`` where ``(r, s)`` represents an ecdsa
            signature of ``val`` with public key ``self * secret_exponent``; and ``recid``
            is the **recovery id**, a number from 0-3 used to eliminate ambiguity about
            which public key signed the value.

        If gen_k is set, it will be called with (n, secret_exponent, val), and an unguessable
        K value should be returned. Otherwise, the default K value, generated according
        to rfc6979 will be used.
        """
        if val == 0:
            raise ValueError()
        if gen_k is None:
            gen_k = deterministic_generate_k
        n = self._order
        k = gen_k(n, secret_exponent, val)
        while True:
            p1 = k * self
            r = p1[0] % n
            s = (self.inverse(k) * (val + (secret_exponent * r) % n)) % n
            if r != 0 and s != 0:
                recid = p1[1] & 1
                if p1[0] > n:
                    recid += 2
                return r, s, recid
            k += 1

    def sign(self, secret_exponent, val, gen_k=None):
        """
        :param: secret_exponent: a :class:`Point <pycoin.ecdsa.Point.Point>` on the curve
        :param: val: an integer value
        :param: gen_k: a function generating __k values__

        :returns: a pair of integers ``(r, s)`` represents an ecdsa signature of ``val``
            with public key ``self * secret_exponent``.

        If gen_k is set, it will be called with (n, secret_exponent, val), and an unguessable
        K value should be returned. Otherwise, the default K value, generated according
        to rfc6979 will be used.
        """
        return self.sign_with_recid(secret_exponent, val, gen_k)[0:2]
