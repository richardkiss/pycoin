from collections import namedtuple

from .serialize import h2b

NetworkValues = namedtuple('NetworkValues',
                           ('network_name', 'subnet_name', 'code', 'wif', 'address', 'pay_to_script', 'prv32', 'pub32'))

NETWORKS = (
    # FAI faircoin mainnet : xprv/xpub
    NetworkValues("Faircoin", "mainnet", "FAI", b'\xdf', b'\x5f', b'\x24', h2b("0488ADE4"), h2b("0488B21E")),
    # FAI faircoin testnet : tprv/tpub
    NetworkValues("Faircoin", "testnet", "FTN", b'\xef', b'\x6f', b'\xc4', h2b("04358394"), h2b("043587CF")),
)


# Map from short code to details about that network.
NETWORK_NAME_LOOKUP = dict((i.code, i) for i in NETWORKS)

# All network names, return in same order as list above: for UI purposes.
NETWORK_NAMES = [i.code for i in NETWORKS]

DEFAULT_NETCODES = NETWORK_NAMES


def _lookup(netcode, property):
    # Lookup a specific value needed for a specific network
    network = NETWORK_NAME_LOOKUP.get(netcode)
    if network:
        return getattr(network, property)
    return None


def network_name_for_netcode(netcode):
    return _lookup(netcode, "network_name")


def subnet_name_for_netcode(netcode):
    return _lookup(netcode, "subnet_name")


def full_network_name_for_netcode(netcode):
    network = NETWORK_NAME_LOOKUP[netcode]
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
