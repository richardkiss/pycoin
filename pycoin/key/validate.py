
from .. import encoding
from .. import networks

DEFAULT_NETCODES = ["BTC"]
DEFAULT_ADDRESS_TYPES = ["address", "pay_to_script"]


def netcode_and_type_for_data(data):
    """
    Given some already-decoded raw data from a base58 string,
    return (N, T) where N is the network code ("BTC" or "LTC") and
    T is the data type ("wif", "address", "prv32", "pub32").
    May also raise EncodingError.
    """
    # TODO: check the data length is within correct range for data type
    INDEX_LIST = [
        ('wif_prefix', "wif"),
        ('address_prefix', "address"),
        ('pay_to_script_prefix', "pay_to_script"),
        ('bip32_pub_prefix', "pub32"),
        ('bip32_priv_prefix', "prv32"),
    ]
    for ni in networks.NETWORKS:
        for attr, name in INDEX_LIST:
            v = getattr(ni, attr, None)
            if v is None:
                continue
            if data.startswith(v):
                return ni.code, name

    raise encoding.EncodingError("unknown prefix")


def _check_against(text, expected_type, allowable_netcodes):
    try:
        data = encoding.a2b_hashed_base58(text)
        netcode, the_type = netcode_and_type_for_data(data)
        if the_type in expected_type and netcode in allowable_netcodes:
            return netcode
    except encoding.EncodingError:
        pass
    return None


def is_address_valid(address, allowable_types=DEFAULT_ADDRESS_TYPES, allowable_netcodes=DEFAULT_NETCODES):
    """
    Accept an address, and a list of allowable address types (a subset of "address" and "pay_to_script"),
    and allowable networks (defaulting to just Bitcoin mainnet), return the network that the address is
    a part of, or None if it doesn't validate.
    """
    return _check_against(address, allowable_types, allowable_netcodes)


def is_wif_valid(wif, allowable_netcodes=DEFAULT_NETCODES):
    """
    Accept a WIF, and a list of allowable networks (defaulting to just Bitcoin mainnet), return
    the network that the wif is a part of, or None if it doesn't validate.
    """
    return _check_against(wif, ["wif"], allowable_netcodes)


def is_public_bip32_valid(hwif, allowable_netcodes=DEFAULT_NETCODES):
    """
    Accept a text representation of a BIP32 public wallet, and a list of allowable networks (defaulting
    to just Bitcoin mainnet), return the network that the wif is a part of, or None if it doesn't validate.
    """
    return _check_against(hwif, ["pub32"], allowable_netcodes)


def is_private_bip32_valid(hwif, allowable_netcodes=DEFAULT_NETCODES):
    """
    Accept a text representation of a BIP32 private wallet, and a list of allowable networks (defaulting
    to just Bitcoin mainnet), return the network that the wif is a part of, or None if it doesn't validate.
    """
    return _check_against(hwif, ["prv32"], allowable_netcodes)
