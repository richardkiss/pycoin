from .Group import Group

# Certicom secp256-k1
_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
_Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
_r = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


secp256k1_group = Group(_p, _a, _b, (_Gx, _Gy), _r)



from .native.openssl import fast_mul, inverse_mod

if fast_mul and inverse_mod:

    class OpenSSLGroup(Group):

        def multiply(self, p, e):
            if e == 0:
                return self._infinity
            return self.Point(*fast_mul(p, e))

        def inverse_mod(self, a, p):
            return inverse_mod(a, p)

    secp256k1_group = OpenSSLGroup(_p, _a, _b, (_Gx, _Gy), _r)
else:
    secp256k1_group = Group(_p, _a, _b, (_Gx, _Gy), _r)
