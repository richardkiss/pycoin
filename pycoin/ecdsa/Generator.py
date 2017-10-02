import os

from .intstream import from_bytes

from .Curve import Curve
from .Point import Point

from .rfc6979 import deterministic_generate_k


class Generator(Curve, Point):
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
        "Return n where n * n == a (mod p). If no such n exists, an arbitrary value will be returned."
        return pow(a, self._mod_sqrt_power, self._p)

    def inverse(self, a):
        "Return n such that a * n == 1 (mod p)."
        return self.inverse_mod(a, self._order)

    def y_values_for_x(self, x):
        """
        Return (y0, y1) where for each y in (y0, y1) (x, y) is a point and y0 is even.

        To get a y value with particular parity, use something like
        ```y_values_for_x(x)[1 if is_y_supposed_to_be_odd else 0]```
        """
        p = self._p
        alpha = (pow(x, 3, p) + self._a * x + self._b) % p
        y0 = self.modular_sqrt(alpha)
        if y0 == 0:
            raise ValueError("no y value for %d" % x)
        y1 = p - y0
        if y0 & 1 == 0:
            return (y0, y1)
        return (y1, y0)

    def possible_public_pairs_for_signature(self, value, signature, y_parity=None):
        """
        yield a list of possible points (public keys) that generated the signature for the given
        value. If y_parity is not None, only one value will be returned; otherwise two values.
        """
        r, s = signature

        try:
            y_vals = self.y_values_for_x(r)
        except ValueError:
            return []

        if y_parity is not None:
            if y_parity & 1:
                y_vals = y_vals[1:]
            else:
                y_vals = y_vals[:1]

        inv_r = self.inverse(r)
        s_over_r = s * inv_r
        minus_E_over_r = -(inv_r * value) * self
        return [s_over_r * self.Point(r, y) + minus_E_over_r for y in y_vals]

    def raw_mul(self, e):
        """Multiply the generator by an integer."""
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
        Verify that signature is a valid signature of hash.
        Return True if and only if the signature is valid.
        """
        order = self._order
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
        Sign val with the given secret_exponent.
        If gen_k is set, it will be called with (n, secret_exponent, val), and an unguessable
        K value should be returned. Otherwise, the default K value, generated according to rfc6979 will be used.
        Returns a tuple of r, s, recid (where recid) is "recovery id", a number from 0-3 used to eliminate
        ambiguity about which public key signed the value.
        """
        if gen_k is None:
            gen_k = deterministic_generate_k
        n = self._order
        k = gen_k(n, secret_exponent, val)
        while True:
            p1 = k * self
            r = p1[0]
            s = (self.inverse(k) * (val + (secret_exponent * r) % n)) % n
            if r != 0 and s != 0:
                recid = p1[1] & 1
                if p1[1] > self._p:
                    recid += 2
                return r, s, recid
            k += 1

    def sign(self, secret_exponent, val, gen_k=None):
        """
        Sign val with the given secret_exponent.
        If gen_k is set, it will be called with (n, secret_exponent, val), and an unguessable
        K value should be returned. Otherwise, the default K value, which follows rfc6979 will be used.
        """
        return self.sign_with_recid(secret_exponent, val, gen_k)[0:2]
