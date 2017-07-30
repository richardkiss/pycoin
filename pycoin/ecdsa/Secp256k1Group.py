from .Group import Group

# Certicom secp256-k1
_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
_Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
_r = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


BestClass = Group


from .native.openssl import fast_mul, inverse_mod

if fast_mul and inverse_mod:

    class OpenSSLGroup(BestClass):

        def multiply(self, p, e):
            if e == 0:
                return self._infinity
            return self.Point(*fast_mul(p, e))

        def inverse_mod(self, a, p):
            return inverse_mod(a, p)

    BestClass = OpenSSLGroup


from .native.secp256k1 import libsecp256k1

if libsecp256k1 is not None:

    class LibSECP256K1GroupBestClass(BestClass):
        def __mul__(self, e):
            if e == 0:
                return self._infinity
            return self.Point(*libsecp256k1._public_pair_for_secret_exponent(e))

        def sign(self, secret_exponent, val, gen_k=None):
            return libsecp256k1._sign(secret_exponent, val, gen_k)

        def verify(self, public_pair, val, sig):
            return libsecp256k1._verify(public_pair, val, sig)

    BestClass = LibSECP256K1GroupBestClass


secp256k1_group = BestClass(_p, _a, _b, (_Gx, _Gy), _r)
