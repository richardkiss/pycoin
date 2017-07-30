from .Secp256k1Group import secp256k1_group

from .Point import Point


def is_public_pair_valid(self, p):
    return self.contains_point(*p)


def possible_public_pairs_for_signature(self, value, signature):
    return list(self.possible_public_pairs_for_signature(value, signature))


def public_pair_for_x(self, x, is_even):
    return self.public_pair_for_x(x, is_even)


def sign(generator, secret_exponent, val, gen_k=None):
    return generator.sign(secret_exponent, val, gen_k)


def verify(generator, public_pair, val, signature):
    return generator.verify(public_pair, val, signature)


generator_secp256k1 = secp256k1_group


def public_pair_for_secret_exponent(g, e):
    return e * g
