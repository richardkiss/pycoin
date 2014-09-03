from .serialize import h2b
from .encoding import EncodingError
from collections import namedtuple
from .block import Block, BitcoinBlock, BitcoinTestNetBlock, LitecoinBlock, BlackcoinBlock

NetworkValues = namedtuple('NetworkValues', 
    ('code', 'network_name',
        'wif_prefix', 'address_prefix',
        'bip32_priv_prefix', 'bip32_pub_prefix',
        'block_class',
        'msg_magic'            # Constant "strMessageMagic" in C++ source code, in file "main.cpp"
    ))

NETWORKS = (
    # Bitcoin
    NetworkValues("BTC", "Bitcoin", b'\x80', b'\0', h2b("0488ADE4"), h2b("0488B21E"),
        BitcoinBlock, 'Bitcoin Signed Message:\n'),

    # Bitcoin Textnet3
    NetworkValues("XTN", "Bitcoin testnet", b'\xef', b'\x6f', h2b("04358394"), h2b("043587CF"),
        BitcoinTestNetBlock, 'Bitcoin Signed Message:\n'),

    # Litecoin
    NetworkValues("LTC", "Litecoin", b'\xb0', b'\x30', None, None,
        LitecoinBlock, 'Litecoin Signed Message:\n'),

    # Dogecoin
    NetworkValues("DOGE", "Dogecoin", b'\x9e', b'\x1e', h2b("02fda4e8"), h2b("02fda923"),
        Block, 'Dogecoin Signed Message:\n'),

    # BlackCoin: unsure about bip32 prefixes; assuming will use Bitcoin's
    NetworkValues("BLK", "Blackcoin", b'\x99', b'\x19', h2b("0488ADE4"), h2b("0488B21E"),
        BlackcoinBlock, 'BlackCoin Signed Message:\n'),
)

# Map from short code to details about that network.
NETWORK_NAME_LOOKUP = dict((i.code, i) for i in NETWORKS)

# All network names, return in same order as list above: for UI purposes.
NETWORK_NAMES = [i.code for i in NETWORKS]

#
# Lookup a specific value needed for a specific network
#
def network_name_for_netcode(netcode):
    return NETWORK_NAME_LOOKUP[netcode].network_name

def wif_prefix_for_netcode(netcode):
    return NETWORK_NAME_LOOKUP[netcode].wif_prefix

def address_prefix_for_netcode(netcode):
    return NETWORK_NAME_LOOKUP[netcode].address_prefix

def prv32_prefix_for_netcode(netcode):
    return NETWORK_NAME_LOOKUP[netcode].bip32_priv_prefix

def pub32_prefix_for_netcode(netcode):
    return NETWORK_NAME_LOOKUP[netcode].bip32_pub_prefix

def transaction_class_for_netcode(netcode):
    # We need to know what class to use for the 
    # transaction for some networks, but most can just use normal Tx
    return NETWORK_NAME_LOOKUP[netcode].block_class.txn_class

def block_class_for_netcode(netcode):
    # We need to know what class to use for the blocks.
    return NETWORK_NAME_LOOKUP[netcode].block_class

def msg_magic_for_netcode(netcode):
    # A short message prefixed with text to be signed/verified by pubkey.
    return NETWORK_NAME_LOOKUP[netcode].msg_magic



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
        ('bip32_pub_prefix', "pub32"),
        ('bip32_priv_prefix', "prv32"),
    ]
    for ni in NETWORKS:
        for attr, name in INDEX_LIST:
            if getattr(ni, attr, None) is None:
                continue
            if data.startswith(getattr(ni, attr)):
                return ni.code, name

    raise EncodingError("unknown prefix")
