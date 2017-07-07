import ctypes.util
import os
import platform

from .bignum import bignum_type_for_library


class BignumContext(ctypes.Structure):
    pass


def set_api(library, api_info):
    for f_name, argtypes, restype in api_info:
        f = getattr(library, f_name)
        f.argtypes = argtypes
        f.restype = restype


def load_library():
    if os.getenv("PYCOIN_NATIVE") != "openssl":
        return None

    system = platform.system()
    if system == 'Windows':
        if platform.architecture()[0] == '64bit':
            library_path = ctypes.util.find_library('libeay64')
        else:
            library_path = ctypes.util.find_library('libeay32')

    else:
        library_path = ctypes.util.find_library('crypto')

    if library_path is None:
        return None

    library = ctypes.CDLL(library_path)

    library.BignumType = bignum_type_for_library(library)

    BN_P = ctypes.POINTER(library.BignumType)
    BN_CTX = ctypes.POINTER(BignumContext)

    BIGNUM_API = [
        ("BN_init", [BN_P], None),
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


def make_fast_mul_f(library):
    NID_secp256k1_GROUP = library.EC_GROUP_new_by_curve_name(714)

    def fast_mul(point, N):
        bn_x = library.BignumType(point.x())
        bn_y = library.BignumType(point.y())
        bn_n = library.BignumType(N)

        ctx = library.BN_CTX_new()
        ec_result = library.EC_POINT_new(NID_secp256k1_GROUP)
        ec_point = library.EC_POINT_new(NID_secp256k1_GROUP)

        library.EC_POINT_set_affine_coordinates_GFp(NID_secp256k1_GROUP, ec_point, bn_x, bn_y, ctx)

        library.EC_POINT_mul(NID_secp256k1_GROUP, ec_result, None, ec_point, bn_n, ctx)

        library.EC_POINT_get_affine_coordinates_GFp(NID_secp256k1_GROUP, ec_result, bn_x, bn_y, ctx)
        library.EC_POINT_free(ec_point)
        library.EC_POINT_free(ec_result)
        library.BN_CTX_free(ctx)
        return type(point)(point.curve(), bn_x.to_int(), bn_y.to_int())
    return fast_mul


def make_inverse_mod_f(library):
    def inverse_mod(a, n):
        ctx = library.BN_CTX_new()
        a1 = library.BignumType(a)
        library.BN_mod_inverse(a1, a1, library.BignumType(n), ctx)
        library.BN_CTX_free(ctx)
        return a1.to_int()
    return inverse_mod


try:
    NATIVE_LIBRARY = load_library()
except:
    NATIVE_LIBRARY = None

if NATIVE_LIBRARY:
    NATIVE_LIBRARY.fast_mul = make_fast_mul_f(NATIVE_LIBRARY)
    NATIVE_LIBRARY.inverse_mod = make_inverse_mod_f(NATIVE_LIBRARY)
