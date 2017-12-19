
def crack_secret_exponent_from_k(generator, signed_value, sig, k):
    """
    Given a signature of a signed_value and a known k, return the secret exponent.
    """
    r, s = sig
    return ((s * k - signed_value) * generator.inverse(r)) % generator.order()


def crack_k_from_sigs(generator, sig1, val1, sig2, val2):
    """
    Given two signatures with the same secret exponent and K value, return that K value.
    """

    # s1 = v1 / k1 + (se * r1) / k1
    # s2 = v2 / k2 + (se * r2) / k2
    # and k = k1 = k2
    # so
    # k * s1 = v1 + (se * r1)
    # k * s2 = v2 + (se * r2)
    # so
    # k * s1 * r2 = r2 * v1 + (se * r1 * r2)
    # k * s2 * r1 = r1 * v2 + (se * r2 * r1)
    # so
    # k (s1 * r2 - s2 * r1) = r2 * v1 - r1 * v2
    # so
    # k = (r2 * v1 - r1 * v2) / (s1 * r2 - s2 * r1)

    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        raise ValueError("r values of signature do not match")
    k = (r2 * val1 - r1 * val2) * generator.inverse(r2 * s1 - r1 * s2)
    return k % generator.order()
