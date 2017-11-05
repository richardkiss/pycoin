
from pycoin.serialize import h2b

from .ScriptTools import BitcoinScriptTools
from .Tx import Tx as BitcoinTx
from pycoin.block import Block as BitcoinBlock

from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.electrum import ElectrumWallet
from pycoin.key.Key import Key
from pycoin.networks.network import Network
from pycoin.ui.KeyParser import KeyParser
from pycoin.ui.uiclass import UI
from pycoin.vm.PayTo import PayTo

# BRAIN DAMAGE
_puzzle_script = PayTo(BitcoinScriptTools)

# BRAIN DAMAGE
mainnet_ui = UI(
    _puzzle_script, bip32_prv_prefix=h2b("0488ade4"), bip32_pub_prefix=h2b("0488B21E"),
    wif_prefix=h2b("80"), sec_prefix="BTCSEC:", address_prefix=h2b("00"),
    pay_to_script_prefix=h2b("05"), bech32_hrp='bc')

mainnet_key = Key.make_subclass(default_ui_context=mainnet_ui)
mainnet_bip32node = BIP32Node.make_subclass(default_ui_context=mainnet_ui)
mainnet_electrum = ElectrumWallet.make_subclass(default_ui_context=mainnet_ui)
mainnet_keyparser = KeyParser(mainnet_ui)

BitcoinMainnet = Network(
    'BTC', "Bitcoin", "mainnet",
    h2b("80"), h2b("00"), h2b("05"), h2b("0488ADE4"), h2b("0488B21E"),
    BitcoinTx, BitcoinBlock,
    h2b('F9BEB4D9'), 8333, [
        "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
        "bitseed.xf2.org", "dnsseed.bluematt.me",
    ],
    bech32_hrp='bc',
    ui=mainnet_ui, keyparser=mainnet_keyparser, key=mainnet_key
)

testnet_ui = UI(
    _puzzle_script, bip32_prv_prefix=h2b("04358394"), bip32_pub_prefix=h2b("043587CF"),
     wif_prefix=h2b("ef"), sec_prefix="XTNSEC:", address_prefix=h2b("6f"),
     pay_to_script_prefix=h2b("c4"), bech32_hrp='tb')

testnet_key = Key.make_subclass(default_ui_context=testnet_ui)
testnet_bip32node = BIP32Node.make_subclass(default_ui_context=testnet_ui)

testnet_keyparser = KeyParser(testnet_ui)

BitcoinTestnet = Network(
    "XTN", "Bitcoin", "testnet3",
    h2b("ef"), h2b("6f"), h2b("c4"), h2b("04358394"), h2b("043587CF"),
    BitcoinTx, BitcoinBlock,
    h2b('0B110907'), 18333, [
        "bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org",
        "bluematt.me", "testnet-seed.bluematt.me"
    ],
    bech32_hrp='tb',
    ui=testnet_ui, keyparser=testnet_keyparser, key=testnet_key
)
