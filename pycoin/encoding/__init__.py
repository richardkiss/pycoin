from .base_conversion import from_long, to_long, EncodingError
from .b58 import b2a_base58, a2b_base58, b2a_hashed_base58, a2b_hashed_base58, is_hashed_base58_valid
from .bytes32 import from_bytes_32, to_bytes_32
from .hash import double_sha256, hash160, ripemd160
from .sec import public_pair_to_sec, sec_to_public_pair, is_sec_compressed, public_pair_to_hash160_sec

from ..intbytes import int2byte


def wif_to_tuple_of_prefix_secret_exponent_compressed(wif):
    """
    Return a tuple of (prefix, secret_exponent, is_compressed).
    """
    decoded = a2b_hashed_base58(wif)
    actual_prefix, private_key = decoded[:1], decoded[1:]
    compressed = len(private_key) > 32
    return actual_prefix, from_bytes_32(private_key[:32]), compressed


def wif_to_tuple_of_secret_exponent_compressed(wif, allowable_wif_prefixes=None):
    """Convert a WIF string to the corresponding secret exponent. Private key manipulation.
    Returns a tuple: the secret exponent, as a bignum integer, and a boolean indicating if the
    WIF corresponded to a compressed key or not.

    Not that it matters, since we can use the secret exponent to generate both the compressed
    and uncompressed Bitcoin address."""
    actual_prefix, secret_exponent, is_compressed = wif_to_tuple_of_prefix_secret_exponent_compressed(wif)
    if allowable_wif_prefixes and actual_prefix not in allowable_wif_prefixes:
        raise EncodingError("unexpected first byte of WIF %s" % wif)
    return secret_exponent, is_compressed


def wif_to_secret_exponent(wif, allowable_wif_prefixes=None):
    """Convert a WIF string to the corresponding secret exponent."""
    return wif_to_tuple_of_secret_exponent_compressed(wif, allowable_wif_prefixes=allowable_wif_prefixes)[0]


def is_valid_wif(wif, allowable_wif_prefixes=[b'\x80']):
    """Return a boolean indicating if the WIF is valid."""
    try:
        wif_to_secret_exponent(wif, allowable_wif_prefixes=allowable_wif_prefixes)
    except EncodingError:
        return False
    return True


def secret_exponent_to_wif(secret_exp, compressed=True, wif_prefix=b'\x80'):
    """Convert a secret exponent (correspdong to a private key) to WIF format."""
    d = wif_prefix + to_bytes_32(secret_exp)
    if compressed:
        d += b'\01'
    return b2a_hashed_base58(d)


def hash160_sec_to_bitcoin_address(hash160_sec, address_prefix=b'\0'):
    """Convert the hash160 of a sec version of a public_pair to a Bitcoin address."""
    return b2a_hashed_base58(address_prefix + hash160_sec)


def bitcoin_address_to_hash160_sec_with_prefix(bitcoin_address):
    """
    Convert a Bitcoin address back to the hash160_sec format and
    also return the prefix.
    """
    blob = a2b_hashed_base58(bitcoin_address)
    if len(blob) != 21:
        raise EncodingError("incorrect binary length (%d) for Bitcoin address %s" %
                            (len(blob), bitcoin_address))
    if blob[:1] not in [b'\x6f', b'\0']:
        raise EncodingError("incorrect first byte (%s) for Bitcoin address %s" % (blob[0], bitcoin_address))
    return blob[1:], blob[:1]


def bitcoin_address_to_hash160_sec(bitcoin_address, address_prefix=b'\0'):
    """Convert a Bitcoin address back to the hash160_sec format of the public key.
    Since we only know the hash of the public key, we can't get the full public key back."""
    hash160, actual_prefix = bitcoin_address_to_hash160_sec_with_prefix(bitcoin_address)
    if (address_prefix == actual_prefix):
        return hash160
    raise EncodingError("Bitcoin address %s for wrong network" % bitcoin_address)


def public_pair_to_bitcoin_address(public_pair, compressed=True, address_prefix=b'\0'):
    """Convert a public_pair (corresponding to a public key) to a Bitcoin address."""
    return hash160_sec_to_bitcoin_address(public_pair_to_hash160_sec(
        public_pair, compressed=compressed), address_prefix=address_prefix)


def is_valid_bitcoin_address(bitcoin_address, allowable_prefixes=b'\0'):
    """Return True if and only if bitcoin_address is valid."""
    try:
        hash160, prefix = bitcoin_address_to_hash160_sec_with_prefix(bitcoin_address)
    except EncodingError:
        return False
    return prefix in allowable_prefixes
