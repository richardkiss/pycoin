from pycoin.serialize import h2b

from .network import Network
from .legacy_networks import NETWORKS

from pycoin.block import Block as BitcoinBlock

from pycoin.coins.bitcoin.networks import BitcoinMainnet, BitcoinTestnet, BitcoinRegtest
from pycoin.coins.litecoin.networks import LitecoinMainnet, LitecoinTestnet

from pycoin.coins.bcash.Tx import Tx as BCashTx
from pycoin.coins.bgold.networks import BGoldMainnet, BGoldTestnet


# BCH bcash mainnet : xprv/xpub
BcashMainnet = Network(
    'BCH', "Bcash", "mainnet",
    BCashTx, BitcoinBlock,
    h2b('F9BEB4D9'), 8333, [
        "seed.bitcoinabc.org", "seed-abc.bitcoinforks.org",
        "btccash-seeder.bitcoinunlimited.info", "seed.bitprim.org",
    ], ui=BitcoinMainnet.ui
)

BUILT_IN_NETWORKS = [

    # BTC bitcoin mainnet : xprv/xpub
    BitcoinMainnet,
    BitcoinTestnet,
    BitcoinRegtest,
    LitecoinMainnet,
    LitecoinTestnet,
    BcashMainnet,
    BGoldMainnet,
    BGoldTestnet,
]


def _transform_NetworkValues_to_Network(nv):
    from pycoin.ecdsa.secp256k1 import secp256k1_generator
    from pycoin.ui.uiclass import UI
    from pycoin.vm.ScriptInfo import ScriptInfo
    from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools

    defaults = dict(
        tx=None, block=None, magic_header=None, dns_bootstrap=[], default_port=None)
    puzzle_script = ScriptInfo(BitcoinScriptTools)
    ui = UI(
        puzzle_script, secp256k1_generator,
        bip32_prv_prefix=nv.prv32, bip32_pub_prefix=nv.pub32,
        wif_prefix=nv.wif, sec_prefix="%sSEC" % nv.code, address_prefix=nv.address,
        pay_to_script_prefix=nv.pay_to_script)
    defaults["ui"] = ui
    u = nv._asdict()
    for k in ['wif', 'address', 'pay_to_script', 'prv32', 'pub32']:
        if k in u:
            del u[k]
    defaults.update(u)
    return Network(**defaults)


def _import_legacy():
    for n in NETWORKS:
        n1 = _transform_NetworkValues_to_Network(n)
        BUILT_IN_NETWORKS.append(n1)


_import_legacy()
