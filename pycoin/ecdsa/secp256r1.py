from .Generator import Generator
from .native.openssl import create_OpenSSLOptimizations, NID_X9_62_prime256v1


_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
_b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
_Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
_r = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


class GeneratorWithOptimizations(create_OpenSSLOptimizations(NID_X9_62_prime256v1), Generator):
    pass


secp256r1_generator = GeneratorWithOptimizations(_p, _a, _b, (_Gx, _Gy), _r)
