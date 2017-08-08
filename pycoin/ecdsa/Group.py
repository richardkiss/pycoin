from .Curve import Curve
from .Point import Point

from .rfc6979 import deterministic_generate_k


class Group(Curve, Point):
    def __new__(self, p, a, b, basis, order):
        return tuple.__new__(self, basis)

    def __init__(self, p, a, b, basis, order):
        Curve.__init__(self, p, a, b, order)
        Point.__init__(self, basis[0], basis[1], self)
        self._powers = []
        Gp = self
        for _ in range(256):
            self._powers.append(Gp)
            Gp += Gp
        assert p % 4 == 3, "p % 4 must be 3 due to modular_sqrt optimization"
        self._mod_sqrt_power = (p + 1) // 4

    def modular_sqrt(self, a):
        return pow(a, self._mod_sqrt_power, self._p)

    def inverse(self, a):
        return self.inverse_mod(a, self._order)

    def y_value_for_x(self, x, y_parity):
        p = self._p
        alpha = (pow(x, 3, p) + self._a * x + self._b) % p
        beta = self.modular_sqrt(alpha)
        if beta == 0:
            return None
        if beta & 1 == y_parity:
            return beta
        return p - beta

    def possible_public_pairs_for_signature(self, value, signature, y_parity=None):
        # y_parity is None, 0 or 1
        r, s = signature

        # recid = nV - 27
        # 1.1
        inv_r = self.inverse(r)
        s_over_r = s * inv_r
        minus_E_over_r = -inv_r * value * self
        x = r

        # BRAIN DAMAGE: this is ugly. We probably need to change the signature of this method
        y_vals = [self.y_value_for_x(x, y_parity=y_parity or 0)]
        if y_parity is None:
            y_vals.append(self._p - y_vals[0])

        l = []
        for y in y_vals:
            # 1.4 the constructor checks that nR is at infinity
            R = self.Point(x, y)
            # 1.6 compute Q = r^-1 (sR - eG)
            Q = s_over_r * R + minus_E_over_r
            # check that Q is the public key
            l.append(Q)
        return l

    def sign_with_y_index(self, secret_exponent, val, gen_k=None):
        if gen_k is None:
            gen_k = deterministic_generate_k
        n = self._order
        k = gen_k(n, secret_exponent, val)
        while True:
            p1 = k * self
            r = p1[0]
            s = (self.inverse(k) * (val + (secret_exponent * r) % n)) % n
            if r != 0 and s != 0:
                return r, s, p1[1] & 1
            k += 1

    def sign(self, secret_exponent, val, gen_k=None):
        return self.sign_with_y_index(secret_exponent, val, gen_k)[0:2]

    def verify(self, public_pair, val, sig):
        """
        Verify that signature is a valid signature of hash.
        Return True if the signature is valid.
        """

        n = self._order
        r, s = sig
        if r < 1 or r > n-1 or s < 1 or s > n-1:
            return False
        s_inverse = self.inverse(s)
        u1 = (val * s_inverse) % n
        u2 = (r * s_inverse) % n
        point = u1 * self + u2 * self.Point(*public_pair)
        v = point[0] % n
        return v == r

    def __mul__(self, e):
        """Multiply the generator by an integer."""
        P = self._infinity
        for bit in range(256):
            # add the power of the generator every time to make it more time-deterministic
            a = [P, P + self._powers[bit]]
            # choose the correct result
            P = a[e & 1]
            e >>= 1
        return P

    def __rmul__(self, e):
        """Multiply the generator by an integer."""
        return self.__mul__(e)
