from collections import namedtuple

from .serialize import h2b

NetworkValues = namedtuple('NetworkValues',
                           ('network_name', 'subnet_name', 'code', 'wif', 'address',
                            'pay_to_script', 'prv32', 'pub32'))

NETWORKS = (

    # BTC bitcoin mainnet : xprv/xpub
    NetworkValues("Bitcoin", "mainnet", "BTC", b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E")),
    # BTC bitcoin testnet : tprv/tpub
    NetworkValues("Bitcoin", "testnet3", "XTN", b'\xef', b'\x6f', b'\xc4',
                  h2b("04358394"), h2b("043587CF")),

    # LTC litecoin mainnet : Ltpv/Ltub
    NetworkValues("Litecoin", "mainnet", "LTC", b'\xb0', b'\x30', b'\5', h2b('019d9cfe'), h2b('019da462')),
    # LTC litecoin testnet : ttpv/ttub
    NetworkValues("Litecoin", "testnet", "XLT", b'\xef', b'\x6f', b'\xc4',
                  h2b('0436ef7d'), h2b('0436f6e1')),

    # VIA viacoin mainnet : xprv/xpub
    NetworkValues("Viacoin", "mainnet", "VIA", b'\xc7', b'\x47', b'\x21', h2b('0488ADE4'), h2b('0488B21E')),
    # VIA viacoin testnet : tprv/tpub
    NetworkValues("Viacoin", "testnet", "TVI", b'\xff', b'\x7f', b'\xc4', h2b('04358394'), h2b('043587CF')),

    # DOGE Dogecoin mainnet : dogv/dogp
    NetworkValues("Dogecoin", "mainnet", "DOGE", b'\x9e', b'\x1e', b'\x16',
                  h2b("02fd3955"), h2b("02fd3929")),

    # BC BlackCoin mainnet : bcpv/bcpb
    NetworkValues("Blackcoin", "mainnet", "BC", b'\x99', b'\x19', None, h2b("02cfbf60"), h2b("02cfbede")),

    # DRK Darkcoin mainnet : drkv/drkp
    NetworkValues("Darkcoin", "mainnet", "DRK", b'\xcc', b'\x4c', None, h2b("02fe52f8"), h2b("02fe52cc")),

    # MEC Megacoin mainnet : mecv/mecp
    NetworkValues("Megacoin", "mainnet", "MEC", b'\xb2', b'\x32', None, h2b("03a04db7"), h2b("03a04d8b")),

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
