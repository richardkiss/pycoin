
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
        BitcoinTx, BitcoinBlock,
        h2b('F9BEB4D9'), 8333, [
            "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
            "bitseed.xf2.org", "dnsseed.bluematt.me",
        ],
        bech32_hrp='bc'
    ),

    # BTC bitcoin mainnet : yprv/ypub
    Network(
        'BTCY', "Bitcoin", "mainnet_segwit_not_native",
        b'\x80', b'\0', b'\5', h2b("049d7878"), h2b("049d7cb2"),
        BitcoinTx, BitcoinBlock,
        h2b('F9BEB4D9'), 8333, [
            "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
            "bitseed.xf2.org", "dnsseed.bluematt.me",
        ],
        bech32_hrp='bc',
        pay_to_script_wit=True
    ),

    # BTC bitcoin mainnet : zprv/zpub
    Network(
        'BTCZ', "Bitcoin", "mainnet_segwit_native",
        b'\x80', b'\0', b'\5', h2b("04b2430c"), h2b("04b24746"),
        BitcoinTx, BitcoinBlock,
        h2b('F9BEB4D9'), 8333, [
            "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
            "bitseed.xf2.org", "dnsseed.bluematt.me",
        ],
        bech32_hrp='bc',
        address_wit=True
    ),

    # BTC bitcoin testnet : tprv/tpub
    Network(
        "XTN", "Bitcoin", "testnet3",
        b'\xef', b'\x6f', b'\xc4', h2b("04358394"), h2b("043587CF"),
        BitcoinTx, BitcoinBlock,
        h2b('0B110907'), 18333, [
            "bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org",
            "bluematt.me", "testnet-seed.bluematt.me"
        ],
        bech32_hrp='tb'
    ),

    # BTC bitcoin testnet : uprv/upub
    # Ref. https://github.com/satoshilabs/slips/blob/master/slip-0132.md#registered-hd-version-bytes
    Network(
        "YTN", "Bitcoin", "testnet3_segwit_not_native",
        b'\xef', b'\x6f', b'\xc4', h2b("044a4e28"), h2b("044a5262"),
        BitcoinTx, BitcoinBlock,
        h2b('0B110907'), 18333, [
            "bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org",
            "bluematt.me", "testnet-seed.bluematt.me"
        ],
        bech32_hrp='tb',
        pay_to_script_wit=True
    ),

    # BTC bitcoin testnet : vprv/vpub
    # Ref. https://github.com/satoshilabs/slips/blob/master/slip-0132.md#registered-hd-version-bytes
    Network(
        "ZTN", "Bitcoin", "testnet3_segwit_native",
        b'\xef', b'\x6f', b'\xc4', h2b("045f18bc"), h2b("045f1cf6"),
        BitcoinTx, BitcoinBlock,
        h2b('0B110907'), 18333, [
            "bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org",
            "bluematt.me", "testnet-seed.bluematt.me"
        ],
        bech32_hrp='tb',
        address_wit=True
    ),

    # LTC litecoin mainnet : Ltpv/Ltub
    Network(
        "LTC", "Litecoin", "mainnet",
        b'\xb0', b'\x30', b'\5',
        h2b('019d9cfe'), h2b('019da462'),
        tx=BitcoinTx, block=BitcoinBlock,
        bech32_hrp='lc'
    ),

    # LTC litecoin testnet : ttpv/ttub
    Network(
        "XLT", "Litecoin", "testnet",
        b'\xef', b'\x6f', b'\xc4',
        h2b('0436ef7d'), h2b('0436f6e1'),
        tx=BitcoinTx, block=BitcoinBlock,
        bech32_hrp='tl'
    )

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
