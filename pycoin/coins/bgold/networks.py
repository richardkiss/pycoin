
from pycoin.serialize import h2b

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from .Tx import Tx as BGoldTx
from ..bitcoin.extras import Extras
from pycoin.block import Block as BGoldBlock

from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.networks.network import Network
from pycoin.ui.uiclass import UI
from pycoin.vm.ScriptInfo import ScriptInfo

# BRAIN DAMAGE
_script_info = ScriptInfo(BitcoinScriptTools)

# BRAIN DAMAGE
mainnet_ui = UI(
    _script_info, secp256k1_generator,
    bip32_prv_prefix=h2b("0488ade4"), bip32_pub_prefix=h2b("0488B21E"),
    wif_prefix=h2b("80"), sec_prefix="BTCSEC:", address_prefix=h2b("26"),
    pay_to_script_prefix=h2b("17"), bech32_hrp='bc')

mainnet_extras = Extras(BitcoinScriptTools, mainnet_ui)

BGoldMainnet = Network(
    'BTG', "BGold", "mainnet",
    BGoldTx, BGoldBlock,
    h2b('e1476d44'), 8338, [
        "eu-dnsseed.bitcoingold-official.org", "dnsseed.bitcoingold.org",
        "dnsseed.btcgpu.org",
    ],
    ui=mainnet_ui, extras=mainnet_extras
)

testnet_ui = UI(
    _script_info, secp256k1_generator,
    bip32_prv_prefix=h2b("04358394"), bip32_pub_prefix=h2b("043587CF"),
    wif_prefix=h2b("ef"), sec_prefix="XTNSEC:", address_prefix=h2b("6f"),
    pay_to_script_prefix=h2b("c4"), bech32_hrp='tb')

testnet_extras = Extras(BitcoinScriptTools, testnet_ui)

BGoldTestnet = Network(
    "XTG", "BGold", "testnet3",
    BGoldTx, BGoldBlock,
    h2b('e1476d44'), 18333, [
        "eu-test-dnsseed.bitcoingold-official.org", "test-dnsseed.bitcoingold.org",
        "test-dnsseed.btcgpu.org", "btg.dnsseed.minertopia.org"
    ],
    ui=testnet_ui, extras=testnet_extras
)
