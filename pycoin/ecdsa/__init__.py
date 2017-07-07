from .Secp256k1Group import secp256k1_group


from .rfc6979 import deterministic_generate_k

is_public_pair_valid = secp256k1_group.contains_point
public_pair_for_x = secp256k1_group.public_pair_for_x
possible_public_pairs_for_signature = secp256k1_group.possible_public_pairs_for_signature

def sign(generator, secret_exponent, val, gen_k=deterministic_generate_k):
    return generator.sign(secret_exponent, val, gen_k)


def verify(generator, public_pair, val, signature):
    return generator.verify(public_pair, val, signature)

#from .ellipticcurve import CurveFp, Point, NoSuchPointError  # noqa

generator_secp256k1 = secp256k1_group


def public_pair_for_secret_exponent(g, e):
    return e * g
