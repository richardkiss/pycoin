from .serialize import h2b
from .encoding import EncodingError

# (network_name, network_code, wif_prefix, address_prefix, bip32_priv_prefix, bip32_pub_prefix)

NETWORKS = (
    ("M", b'\x80', b'\0', h2b("0488ADE4"), h2b("0488B21E"), "Bitcoin"),
    ("T", b'\xef', b'\x6f', h2b("04358394"), h2b("043587CF"), "Bitcoin testnet"),
    ("L", b'\xb0', b'0', None, None, "Litecoin"),
    ("D", b'\x9e', b'\x1e', h2b("02fda4e8"), h2b("02fda923"), "Dogecoin", ),
)

CODE_INDEX = 0
WIF_INDEX = 1
ADDRESS_INDEX = 2
PRV_32_INDEX = 3
PUB_32_INDEX = 4
NAME_INDEX = -1

NETWORK_INDEX_LOOKUP = dict((n[CODE_INDEX], k) for k, n in enumerate(NETWORKS))


def network_name_for_netcode(netcode):
    idx = NETWORK_INDEX_LOOKUP.get(netcode)
    return NETWORKS[idx][NAME_INDEX]


def wif_prefix_for_netcode(netcode):
    idx = NETWORK_INDEX_LOOKUP.get(netcode)
    return NETWORKS[idx][WIF_INDEX]


def address_prefix_for_netcode(netcode):
    idx = NETWORK_INDEX_LOOKUP.get(netcode)
    return NETWORKS[idx][ADDRESS_INDEX]


def prv32_prefix_for_netcode(netcode):
    idx = NETWORK_INDEX_LOOKUP.get(netcode)
    return NETWORKS[idx][PRV_32_INDEX]


def pub32_prefix_for_netcode(netcode):
    idx = NETWORK_INDEX_LOOKUP.get(netcode)
    return NETWORKS[idx][PUB_32_INDEX]


def netcode_and_type_for_data(data):
    """
    Return (N, T) where N is the network code ("M" or "T") and
    T is the key type ("wif", "address", "prv32", "pub32"), bin_data is the decoded binary
    data for the given text. May also raise EncodingError.
    """
    INDEX_LIST = [
        (WIF_INDEX, "wif"),
        (ADDRESS_INDEX, "address"),
        (PUB_32_INDEX, "pub32"),
        (PRV_32_INDEX, "prv32"),
    ]
    for ni in NETWORKS:
        for idx, name in INDEX_LIST:
            if ni[idx] is None:
                continue
            if data.startswith(ni[idx]):
                return ni[CODE_INDEX], name

    raise EncodingError("unknown prefix")
