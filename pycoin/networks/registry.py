from .all import BUILT_IN_NETWORKS
from .network import Network


def clear_all_networks():
    global _NETWORK_NAME_LOOKUP, _NETWORK_PREFIXES, _NETWORK_CODES, _BECH32_PREFIXES
    _NETWORK_NAME_LOOKUP = {}
    _NETWORK_PREFIXES = {}
    _BECH32_PREFIXES = {}
    _NETWORK_CODES = []


clear_all_networks()


def register_network(network_info):
    """
    Accept a Network instance and register it in the database
    by its netcode.
    """
    assert isinstance(network_info, Network)
    code = network_info.code
    if code in _NETWORK_NAME_LOOKUP:
        if _NETWORK_NAME_LOOKUP[code] == network_info:
            return
        raise ValueError("code %s already defined" % code)
    _NETWORK_NAME_LOOKUP[code] = network_info
    _NETWORK_CODES.append(code)
    for prop in "wif address pay_to_script prv32 pub32".split():
        v = getattr(network_info, prop, None)
        if v is not None:
            if v not in _NETWORK_PREFIXES:
                _NETWORK_PREFIXES[v] = []
            _NETWORK_PREFIXES[v].append((code, prop))
    v = getattr(network_info, "bech32_hrp", None)
    if v is not None:
        if v not in _BECH32_PREFIXES:
            _BECH32_PREFIXES[v] = []
        _BECH32_PREFIXES[v].append(code)


def _register_default_networks():
    for network in BUILT_IN_NETWORKS:
        register_network(network)


def network_for_netcode(netcode):
    """
    Return the given Network object for the given netcode (or None).
    """
    return _NETWORK_NAME_LOOKUP.get(netcode)


def network_codes():
    """
    Return a list of registered netcodes, in the order they were registered.
    """
    return _NETWORK_CODES


def network_prefixes():
    """
    Return a dictionary of 1 and 4 byte prefixes that returns a list of pairs (a, b) where
    a is the netcode and b is one of "wif", "address", "pay_to_script", "prv32", "pub32" or "segwit".
    """
    return _NETWORK_PREFIXES


def bech32_prefixes():
    """
    Return a dictionary of 2 byte prefixes that returns a list of netcodes that have this prefix.
    """
    return _BECH32_PREFIXES


def _lookup(netcode, property):
    # Lookup a specific value needed for a specific network
    network = _NETWORK_NAME_LOOKUP.get(netcode)
    if network:
        return getattr(network, property)
    return None


def network_name_for_netcode(netcode):
    "Return the network name for the given netcode (or None)"
    return _lookup(netcode, "network_name")


def subnet_name_for_netcode(netcode):
    """
    Return the subnet network name for the given netcode (or None).
    This is usually "testnet" or "mainnet".
    """
    return _lookup(netcode, "subnet_name")


def full_network_name_for_netcode(netcode):
    "Return the full network name for the given netcode (or None)"
    network = _NETWORK_NAME_LOOKUP[netcode]
    if network:
        return "%s %s" % (network.network_name, network.subnet_name)


def wif_prefix_for_netcode(netcode):
    "Return the 1 byte prefix for WIFs for the given netcode (or None)"
    return _lookup(netcode, "wif")


def address_prefix_for_netcode(netcode):
    "Return the 1 byte prefix for addresses for the given netcode (or None)"
    return _lookup(netcode, "address")


def bech32_hrp_for_netcode(netcode):
    "Return the bech32 hrp prefix for addresses for the given netcode (or None)"
    return _lookup(netcode, "bech32_hrp")


def pay_to_script_prefix_for_netcode(netcode):
    "Return the 1 byte prefix for pay-to-script addresses for the given netcode (or None)"
    return _lookup(netcode, "pay_to_script")


def prv32_prefix_for_netcode(netcode):
    "Return the 4 byte prefix for private BIP32 addresses for the given netcode (or None)"
    return _lookup(netcode, "prv32")


def pub32_prefix_for_netcode(netcode):
    "Return the 4 byte prefix for public BIP32 addresses for the given netcode (or None)"
    return _lookup(netcode, "pub32")


_register_default_networks()
