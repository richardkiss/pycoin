import ctypes.util
import os
import platform

from .bignum import bignum_type_for_library


NID_X9_62_prime256v1 = 415
NID_secp256k1 = 714


class BignumContext(ctypes.Structure):
    pass


def set_api(library, api_info):
    for f_name, argtypes, restype in api_info:
        f = getattr(library, f_name)
        f.argtypes = argtypes
        f.restype = restype


def load_library():
    system = platform.system()
    PYCOIN_LIBCRYPTO_PATH = os.getenv("PYCOIN_LIBCRYPTO_PATH")

    if PYCOIN_LIBCRYPTO_PATH:
        library_path = PYCOIN_LIBCRYPTO_PATH
    elif system == 'Windows':
        if platform.architecture()[0] == '64bit':
            library_path = ctypes.util.find_library('libeay64')
        else:
            library_path = ctypes.util.find_library('libeay32')

    else:
        # on Mac OS 10.15.1 trying to load "libcrypto" crashes
        # but crypto.0.9.8 works, so try to load that one first
        for p in ["crypto.0.9.8", "crypto"]:
            library_path = ctypes.util.find_library(p)
            if library_path:
                break

    if library_path is None:
        return None

    library = ctypes.CDLL(library_path)

    library.BignumType = bignum_type_for_library(library)

    BN_P = ctypes.POINTER(library.BignumType)
    BN_CTX = ctypes.POINTER(BignumContext)

    BIGNUM_API = [
        ("BN_new", [], BN_P),
        ("BN_set_word", [BN_P, ctypes.c_ulong], ctypes.c_int),
        ("BN_clear_free", [BN_P], None),
        ("BN_bin2bn", [ctypes.c_char_p, ctypes.c_int, BN_P], BN_P),
        ("BN_mod_inverse", [BN_P, BN_P, BN_P, BN_CTX], BN_P),
        ("BN_CTX_new", [], BN_CTX),
        ("BN_CTX_free", [BN_CTX], None),
        ("BN_mpi2bn", [ctypes.c_char_p, ctypes.c_int, BN_P], BN_P),
    ]

    ECC_API = [
        ("EC_GROUP_new_by_curve_name", [ctypes.c_int], ctypes.c_void_p),
        ("EC_POINT_new", [ctypes.c_void_p], ctypes.c_void_p),  # TODO: make this a EC_POINT type
        ("EC_POINT_free", [ctypes.c_void_p], None),
        ("EC_POINT_set_affine_coordinates_GFp",
            [ctypes.c_void_p, ctypes.c_void_p, BN_P, BN_P, BN_CTX], ctypes.c_int),
        ("EC_POINT_get_affine_coordinates_GFp",
            [ctypes.c_void_p, ctypes.c_void_p, BN_P, BN_P, BN_CTX], ctypes.c_int),
        ("EC_POINT_mul",
            [ctypes.c_void_p, ctypes.c_void_p, BN_P, ctypes.c_void_p, BN_P, BN_CTX], ctypes.c_int),
    ]
    set_api(library, BIGNUM_API)
    set_api(library, ECC_API)
    return library


OpenSSL = load_library()


def create_OpenSSLOptimizations(curve_id):

    class noop:
        pass

    native = os.getenv("PYCOIN_NATIVE")
    if native and native.lower() != "openssl":
        return noop

    if not OpenSSL:
        return noop

    class Optimizations:

        if OpenSSL:
            openssl_group = OpenSSL.EC_GROUP_new_by_curve_name(curve_id)

        def multiply(self, p, e):
            "Use OpenSSL to perform point multiplication."
            if self._order:
                e %= self._order
            if e == 0 or p == self._infinity:
                return self._infinity

            bn_x = OpenSSL.BignumType(p[0])
            bn_y = OpenSSL.BignumType(p[1])
            bn_n = OpenSSL.BignumType(e)

            ctx = OpenSSL.BN_CTX_new()
            ec_result = OpenSSL.EC_POINT_new(self.openssl_group)
            ec_point = OpenSSL.EC_POINT_new(self.openssl_group)

            OpenSSL.EC_POINT_set_affine_coordinates_GFp(self.openssl_group, ec_point, bn_x, bn_y, ctx)

            OpenSSL.EC_POINT_mul(self.openssl_group, ec_result, None, ec_point, bn_n, ctx)

            OpenSSL.EC_POINT_get_affine_coordinates_GFp(self.openssl_group, ec_result, bn_x, bn_y, ctx)
            OpenSSL.EC_POINT_free(ec_point)
            OpenSSL.EC_POINT_free(ec_result)
            OpenSSL.BN_CTX_free(ctx)
            return self.Point(bn_x.to_int(), bn_y.to_int())

        def raw_mul(self, e):
            """Multiply the generator by an integer."""
            return self.multiply(self, e)

        def inverse_mod(self, a, p):
            ctx = OpenSSL.BN_CTX_new()
            a1 = OpenSSL.BignumType(a)
            OpenSSL.BN_mod_inverse(a1, a1, OpenSSL.BignumType(p), ctx)
            OpenSSL.BN_CTX_free(ctx)
            return a1.to_int()

    return Optimizations
