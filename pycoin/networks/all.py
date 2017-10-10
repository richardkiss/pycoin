
from .network import Network
from .legacy_networks import NETWORKS

from pycoin.block import Block as BitcoinBlock
from pycoin.coins.bitcoin.Tx import Tx as BitcoinTx

from pycoin.coins.bitcoin.networks import BitcoinMainnet, BitcoinTestnet

from pycoin.coins.bcash.Tx import Tx as BCashTx

from ..serialize import h2b



# lightcoin

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.vm.PuzzleScripts import PuzzleScripts
from pycoin.ui.uiclass import UI

_puzzle_script = PuzzleScripts(BitcoinScriptTools)

ltc_ui = UI(_puzzle_script, address_prefix=h2b("30"), pay_to_script_prefix=h2b("05"), bech32_hrp='lc')
xlt_ui = UI(_puzzle_script, address_prefix=h2b("6f"), pay_to_script_prefix=h2b("c4"), bech32_hrp='tl')


BUILT_IN_NETWORKS = [

    # BTC bitcoin mainnet : xprv/xpub
    BitcoinMainnet,
    BitcoinTestnet,

    # LTC litecoin mainnet : Ltpv/Ltub
    Network(
        "LTC", "Litecoin", "mainnet",
        b'\xb0', b'\x30', b'\5',
        h2b('019d9cfe'), h2b('019da462'),
        tx=BitcoinTx, block=BitcoinBlock,
        bech32_hrp='lc',
        ui=ltc_ui
    ),

    # LTC litecoin testnet : ttpv/ttub
    Network(
        "XLT", "Litecoin", "testnet",
        b'\xef', b'\x6f', b'\xc4',
        h2b('0436ef7d'), h2b('0436f6e1'),
        tx=BitcoinTx, block=BitcoinBlock,
        bech32_hrp='tl',
        ui=xlt_ui
    ),

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
