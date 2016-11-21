
from .network import Network
from .legacy_networks import NETWORKS

from pycoin.tx.Tx import Tx as BitcoinTx
from pycoin.block import Block as BitcoinBlock

from ..serialize import h2b

BUILT_IN_NETWORKS = [

    # BTC bitcoin mainnet : xprv/xpub
    Network(
        'BTC', "Bitcoin", "mainnet",
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        b'\6', b'\x0a',
        BitcoinTx, BitcoinBlock,
        h2b('F9BEB4D9'), 8333, [
            "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
            "bitseed.xf2.org", "dnsseed.bluematt.me",
        ]
    ),

    # BTC bitcoin testnet : tprv/tpub
    Network(
        "XTN", "Bitcoin", "testnet3",
        b'\xef', b'\x6f', b'\xc4', h2b("04358394"), h2b("043587CF"),
        b'\3', b'\x28',
        BitcoinTx, BitcoinBlock,
        h2b('0B110907'), 18333, [
            "bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org",
            "bluematt.me", "testnet-seed.bluematt.me"
        ]
    )
]


def _transform_NetworkValues_to_Network(nv):
    defaults = dict(
        tx=None, block=None, magic_header=None, dns_bootstrap=[], default_port=None,
        address_wit=None, pay_to_script_wit=None)
    defaults.update(nv._asdict())
    return Network(**defaults)


def _import_legacy():
    for n in NETWORKS:
        n1 = _transform_NetworkValues_to_Network(n)
        BUILT_IN_NETWORKS.append(n1)


_import_legacy()
