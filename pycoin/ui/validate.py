from pycoin.ui.Parser import parseable_str

## THIS FILE IS DEPRECATED
# Please use network.parse.* instead

DEFAULT_ADDRESS_TYPES = ["p2pkh", "p2sh"]


def network_for_netcodes(netcodes):
    from ..networks.registry import network_codes, network_for_netcode
    if netcodes is None:
        netcodes = network_codes()
    return [network_for_netcode(netcode) for netcode in netcodes]


def is_address_valid(address, allowable_types=None, allowable_netcodes=None):
    """
    Accept an address, and a list of allowable address types (for example, "p2pkh" and "p2sh"),
    and allowable networks (defaulting to just Bitcoin mainnet), return the network that the address is
    a part of, or None if it doesn't validate.
    """
    networks = network_for_netcodes(allowable_netcodes)
    address = parseable_str(address)
    for network in networks:
        k = network.parse.address(address)
        if k:
            if allowable_types is None or k.info()["type"] in allowable_types:
                return network.symbol
    return None


def _is_key_valid(text, allowable_netcodes, info_filter_f, types=["key"]):
    networks = network_for_netcodes(allowable_netcodes)
    text = parseable_str(text)
    for network in networks:
        k = network.parse.parse_to_info(text, types=types)
        if k:
            if info_filter_f(k):
                return network.symbol
    return None


def is_wif_valid(wif, allowable_netcodes=None):
    """
    Accept a WIF, and a list of allowable networks (defaulting to just Bitcoin mainnet), return
    the network that the wif is a part of, or None if it doesn't validate.
    """

    wif = parseable_str(wif)
    networks = network_for_netcodes(allowable_netcodes)
    for network in networks:
        if network.parse.wif(wif):
            return network.symbol


def is_public_bip32_valid(hwif, allowable_netcodes=None):
    """
    Accept a text representation of a BIP32 public wallet, and a list of allowable networks (defaulting
    to just Bitcoin mainnet), return the network that the wif is a part of, or None if it doesn't validate.
    """
    hwif = parseable_str(hwif)
    networks = network_for_netcodes(allowable_netcodes)
    for network in networks:
        if network.parse.bip32_pub(hwif):
            return network.symbol


def is_private_bip32_valid(hwif, allowable_netcodes=None):
    """
    Accept a text representation of a BIP32 private wallet, and a list of allowable networks (defaulting
    to just Bitcoin mainnet), return the network that the wif is a part of, or None if it doesn't validate.
    """
    hwif = parseable_str(hwif)
    networks = network_for_netcodes(allowable_netcodes)
    for network in networks:
        if network.parse.bip32_prv(hwif):
            return network.symbol
