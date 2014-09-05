from .. import encoding
from .validate import netcode_and_type_for_text


def key_from_text(text, is_compressed=True):
    """
    This function will accept a BIP0032 wallet string, a WIF, or a bitcoin address.

    The "is_compressed" parameter is ignored unless a public address is passed in.
    """
    # TODO: fix import loop
    from .BIP32Node import BIP32Node
    from .Key import Key

    netcode, key_type, data = netcode_and_type_for_text(text)

    if key_type in ("pub32", "prv32"):
        return BIP32Node.from_wallet_key(text)

    if key_type == 'wif':
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        return Key(
            secret_exponent=encoding.from_bytes_32(data),
            prefer_uncompressed=not is_compressed, netcode=netcode)
    if key_type == 'address':
        return Key(hash160=data, is_compressed=is_compressed, netcode=netcode)
    raise encoding.EncodingError("unknown text: %s" % text)
