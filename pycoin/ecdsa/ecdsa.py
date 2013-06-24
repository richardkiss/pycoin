
import os

from . import ellipticcurve, numbertheory

def sign(generator, secret_exponent, val, k=None, entropy_generator=os.urandom):
        """Return a signature for the provided hash, using the provided
        random nonce.  It is absolutely vital that random_k be an unpredictable
        number in the range [1, self.public_key.point.order()-1].  If
        an attacker can guess random_k, he can compute our private key from a
        single signature.  Also, if an attacker knows a few high-order
        bits (or a few low-order bits) of random_k, he can compute our private
        key from many signatures.  The generation of nonces with adequate
        cryptographic strength is very difficult and far beyond the scope
        of this comment.

        May raise RuntimeError, in which case retrying with a new
        random value k is in order.
        """
        G = generator
        n = G.order()
        if k is None:
            k = int.from_bytes(entropy_generator((n.bit_length()+7)//8), byteorder='big')
        k = k % n
        p1 = k * G
        r = p1.x()
        if r == 0: raise RuntimeError("amazingly unlucky random number r")
        s = ( numbertheory.inverse_mod( k, n ) * \
              ( val + ( secret_exponent * r ) % n ) ) % n
        if s == 0: raise RuntimeError("amazingly unlucky random number s")
        return (r, s)

def public_pair_for_secret_exponent(generator, secret_exponent):
    return (generator*secret_exponent).pair()

def public_pair_for_x(generator, x, is_even):
    curve = generator.curve()
    alpha = ( x * x * x  + curve.a() * x + curve.b() ) % curve.p()
    beta = numbertheory.modular_sqrt(alpha, curve.p())
    if is_even == bool(beta & 1):
        return (x, generator.curve().p() - beta)
    return (x, beta)

def verify(generator, public_point, val, signature):
    """Verify that signature is a valid signature of hash.
    Return True if the signature is valid.
    """

    # From X9.62 J.3.1.

    G = generator
    n = G.order()
    r, s = signature
    if r < 1 or r > n-1: return False
    if s < 1 or s > n-1: return False
    c = numbertheory.inverse_mod( s, n )
    u1 = ( val * c ) % n
    u2 = ( r * c ) % n
    point = u1 * G + u2 * ellipticcurve.Point( G.curve(), public_point[0], public_point[1], G.order() )
    v = point.x() % n
    return v == r

def possible_public_pairs_for_signature(generator, value, signature):
    """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
    #from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
    G = generator
    curve = G.curve()
    order = G.order()

    r,s = signature

    possible_points = set()

    #recid = nV - 27
    # 1.1
    inv_r = numbertheory.inverse_mod(r,order)
    minus_e = -value % order
    x = r
    # 1.3
    alpha = ( x * x * x  + curve.a() * x + curve.b() ) % curve.p()
    beta = numbertheory.modular_sqrt(alpha, curve.p())
    for y in [beta, curve.p() - beta]:
        # 1.4 the constructor checks that nR is at infinity
        R = ellipticcurve.Point(curve, x, y, order)
        # 1.6 compute Q = r^-1 (sR - eG)
        Q = inv_r * ( s * R + minus_e * G )
        public_pair = (Q.x(), Q.y())
        # check that Q is the public key
        if verify(generator, public_pair, value, signature):
        # check that we get the original signing address
            possible_points.add(public_pair)
    return possible_points
