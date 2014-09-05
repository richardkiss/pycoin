
import binascii
from .. import encoding
from ..networks import DEFAULT_NETCODES, NETWORK_NAMES, NETWORKS
from ..serialize import h2b

DEFAULT_ADDRESS_TYPES = ["address", "pay_to_script"]

def _generate_network_prefixes():
    d = {}
    for n in NETWORKS:
        for prop in "wif address pay_to_script prv32 pub32".split():
            v = getattr(n, prop, None)
            if v:
                if v not in d:
                    d[v] = []
                d[v].append((n, prop))
    return d


NETWORK_PREFIXES = _generate_network_prefixes()


def netcode_and_type_for_data(data, netcodes=NETWORK_NAMES):
    """
    Given some already-decoded raw data from a base58 string,
    return (N, T) where N is the network code ("BTC" or "LTC") and
    T is the data type ("wif", "address", "public_pair", "prv32", "pub32").
    May also raise EncodingError.
    """
    d = {}
    for length in (4, 1):
        for network, the_type in NETWORK_PREFIXES.get(data[:length], []):
            d[network.code] = the_type
    for netcode in netcodes:
        v = d.get(netcode)
        if v:
            return netcode, v

    raise encoding.EncodingError("unknown prefix")


def netcode_and_type_for_text(text):
    # check for "public pair"
    try:
        LENGTH_LOOKUP = {
            33: "public_pair",
            65: "public_pair",
            16: "elc_seed",
            32: "elc_prv",
            64: "elc_pub",
        }
        as_bin = h2b(text)
        l = len(as_bin)
        if l in LENGTH_LOOKUP:
            return None, LENGTH_LOOKUP[l], as_bin
    except (binascii.Error, TypeError):
        pass

    data = encoding.a2b_hashed_base58(text)
    netcode, the_type = netcode_and_type_for_data(data)
    length = 1 if the_type in ["wif", "address"] else 4
    return netcode, the_type, data[length:]


def _check_against(text, expected_type, allowable_netcodes):
    try:
        data = encoding.a2b_hashed_base58(text)
        netcode, the_type = netcode_and_type_for_data(data, netcodes=allowable_netcodes)
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
