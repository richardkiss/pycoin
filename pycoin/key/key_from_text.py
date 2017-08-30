from .. import encoding
from ..serialize import b2h
from .validate import netcode_and_type_for_text
from .electrum import ElectrumWallet
from .BIP32Node import BIP32Node
from .Key import Key


def key_from_hwif(b58_str):
    """Generate a Wallet from a base58 string in a standard way."""

    data = a2b_hashed_base58(b58_str)
    netcode, key_type, length = netcode_and_type_for_data(data)

    if key_type not in ("pub32", "prv32"):
        raise EncodingError("bad wallet key header")

    is_private = (key_type == 'prv32')
    parent_fingerprint, child_index = struct.unpack(">4sL", data[5:13])

    d = dict(chain_code=data[13:45], depth=ord(data[4:5]),
             parent_fingerprint=parent_fingerprint, child_index=child_index)

    if is_private:
        if data[45:46] != b'\0':
            raise EncodingError("private key encoded wrong")
        d["secret_exponent"] = from_bytes_32(data[46:])
    else:
        d["public_pair"] = sec_to_public_pair(data[45:])

    return BIP32Node(**d)


def key_from_text(text, key_types=None):
    """
    This function will accept a BIP0032 wallet string, a WIF, or a bitcoin address.
    """
    netcode, key_type, data = netcode_and_type_for_text(text)
    if key_types and (key_type not in key_types):
        return None, None

    if key_type in ("pub32", "prv32"):
        return BIP32Node.from_hwif(text), netcode

    if key_type == 'wif':
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        return Key(
            secret_exponent=encoding.from_bytes_32(data),
            prefer_uncompressed=not is_compressed), netcode

    if key_type == 'address':
        return Key(hash160=data), netcode

    if key_type == 'elc_seed':
        return ElectrumWallet(initial_key=b2h(data)), None

    if key_type == 'elc_prv':
        return ElectrumWallet(master_private_key=encoding.from_bytes_32(data)), None

    if key_type == 'elc_pub':
        return ElectrumWallet(master_public_key=data), None

    return None, None
