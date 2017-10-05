import struct

from ..encoding import from_bytes_32, sec_to_public_pair, EncodingError
from ..serialize import b2h

from .validate import netcode_and_type_for_text

from pycoin.key.electrum import ElectrumWallet
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.Key import Key


def bip32_from_data(generator, data, is_private):
    """Generate a Wallet from a base58 string in a standard way."""

    parent_fingerprint, child_index = struct.unpack(">4sL", data[1:9])

    d = dict(generator=generator, chain_code=data[9:41], depth=ord(data[0:1]),
             parent_fingerprint=parent_fingerprint, child_index=child_index)

    if is_private:
        if data[41:42] != b'\0':
            raise EncodingError("private key encoded wrong")
        d["secret_exponent"] = from_bytes_32(data[42:])
    else:
        d["public_pair"] = sec_to_public_pair(data[41:], generator)

    return BIP32Node(**d)


def key_from_text(generator, text, is_compressed=True, key_types=None):
    """
    This function will accept a BIP0032 wallet string, a WIF, or a bitcoin address.
    """

    netcode, key_type, data = netcode_and_type_for_text(text)
    if key_types and (key_type not in key_types):
        return None, None

    if key_type in ("pub32", "prv32"):
        is_private = (key_type == 'prv32')
        return bip32_from_data(generator, data, is_private), netcode

    if key_type == 'wif':
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        return Key(
            secret_exponent=from_bytes_32(data),
            generator=generator,
            prefer_uncompressed=not is_compressed), netcode

    if key_type == 'address':
        return Key(hash160=data), netcode

    if key_type == 'elc_seed':
        return ElectrumWallet(initial_key=b2h(data), generator=generator), None

    if key_type == 'elc_prv':
        return ElectrumWallet(master_private_key=from_bytes_32(data), generator=generator), None

    if key_type == 'elc_pub':
        return ElectrumWallet(master_public_key=data, generator=generator), None

    return None, None
