from .Generator import Generator
from .native.openssl import create_OpenSSLOptimizations, NID_secp256k1
from .native.secp256k1 import LibSECP256K1Optimizations

# from http://www.secg.org/sec2-v2.pdf

_a = 0x0000000000000000000000000000000000000000000000000000000000000000
_b = 0x0000000000000000000000000000000000000000000000000000000000000007
_p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
_Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
_r = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


# include optimizations from libsecp256k1 and openssl, if available

class GeneratorWithOptimizations(LibSECP256K1Optimizations, create_OpenSSLOptimizations(NID_secp256k1), Generator):
    pass


secp256k1_generator = GeneratorWithOptimizations(_p, _a, _b, (_Gx, _Gy), _r)
