from pycoin.serialize import h2b

from .network import Network
from .legacy_networks import NETWORKS

from pycoin.block import Block as BitcoinBlock

from pycoin.coins.bitcoin.networks import BitcoinMainnet, BitcoinTestnet
from pycoin.coins.litecoin.networks import LitecoinMainnet, LitecoinTestnet

from pycoin.coins.bcash.Tx import Tx as BCashTx


BUILT_IN_NETWORKS = [

    # BTC bitcoin mainnet : xprv/xpub
    BitcoinMainnet,
    BitcoinTestnet,
    LitecoinMainnet,
    LitecoinTestnet,

    # BCH bcash mainnet : xprv/xpub
    Network(
        'BCH', "Bcash", "mainnet",
        b'\x80', b'\0', b'\5', h2b("0488ADE4"), h2b("0488B21E"),
        BCashTx, BitcoinBlock,
        h2b('F9BEB4D9'), 8333, [
            "seed.bitcoinabc.org", "seed-abc.bitcoinforks.org",
            "btccash-seeder.bitcoinunlimited.info", "seed.bitprim.org",
        ]
    ),

]


def _transform_NetworkValues_to_Network(nv):
    defaults = dict(
        tx=None, block=None, magic_header=None, dns_bootstrap=[], default_port=None, bech32_hrp=None)
    defaults.update(nv._asdict())
    return Network(**defaults)


def _import_legacy():
    for n in NETWORKS:
        n1 = _transform_NetworkValues_to_Network(n)
        BUILT_IN_NETWORKS.append(n1)


_import_legacy()
