from .all import BUILT_IN_NETWORKS


_NETWORK_NAME_LOOKUP = {}

_NETWORK_PREFIXES = {}

_NETWORK_CODES = []


def register_network(network_info):
    code = network_info.code
    if code in _NETWORK_NAME_LOOKUP:
        raise ValueError("code %s already defined" % code)
    _NETWORK_NAME_LOOKUP[code] = network_info
    _NETWORK_CODES.append(code)
    for prop in "wif address pay_to_script prv32 pub32".split():
        v = getattr(network_info, prop, None)
        if v is not None:
            if v not in _NETWORK_PREFIXES:
                _NETWORK_PREFIXES[v] = []
            _NETWORK_PREFIXES[v].append((code, prop))


def _register_default_networks():
    for network in BUILT_IN_NETWORKS:
        register_network(network)


def network_for_netcode(netcode):
    return _NETWORK_NAME_LOOKUP.get(netcode)


def network_codes():
    return _NETWORK_CODES


def network_prefixes():
    return _NETWORK_PREFIXES


def _lookup(netcode, property):
    # Lookup a specific value needed for a specific network
    network = _NETWORK_NAME_LOOKUP.get(netcode)
    if network:
        return getattr(network, property)
    return None


def network_name_for_netcode(netcode):
    return _lookup(netcode, "network_name")


def subnet_name_for_netcode(netcode):
    return _lookup(netcode, "subnet_name")


def full_network_name_for_netcode(netcode):
    network = _NETWORK_NAME_LOOKUP[netcode]
    if network:
        return "%s %s" % (network.network_name, network.subnet_name)


def wif_prefix_for_netcode(netcode):
    return _lookup(netcode, "wif")


def address_prefix_for_netcode(netcode):
    return _lookup(netcode, "address")


def pay_to_script_prefix_for_netcode(netcode):
    return _lookup(netcode, "pay_to_script")


def prv32_prefix_for_netcode(netcode):
    return _lookup(netcode, "prv32")


def pub32_prefix_for_netcode(netcode):
    return _lookup(netcode, "pub32")


_register_default_networks()
