
from pycoin.serialize import h2b

from .ScriptTools import BitcoinScriptTools
from .Tx import Tx as BitcoinTx
from .KeyParser import KeyParser
from pycoin.block import Block as BitcoinBlock

from pycoin.networks.network import Network
from pycoin.ui.uiclass import UI
from pycoin.vm.PayTo import PayTo

_puzzle_script = PayTo(BitcoinScriptTools)


mainnet_ui = UI(_puzzle_script, address_prefix=h2b("00"), pay_to_script_prefix=h2b("05"), bech32_hrp='bc')
mainnet_keyparser = KeyParser(
    netcode="BTC", wif_prefix=h2b("80"), address_prefix=h2b("00"),
    bip32_prv_prefix=h2b("0488ade4"), bip32_pub_prefix=h2b("0488B21E"), bech32_prefix="bc")

BitcoinMainnet = Network(
    'BTC', "Bitcoin", "mainnet",
    h2b("80"), h2b("00"), h2b("05"), h2b("0488ADE4"), h2b("0488B21E"),
    BitcoinTx, BitcoinBlock,
    h2b('F9BEB4D9'), 8333, [
        "seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org",
        "bitseed.xf2.org", "dnsseed.bluematt.me",
    ],
    bech32_hrp='bc',
    ui=mainnet_ui, keyparser=mainnet_keyparser
)


testnet_ui = UI(_puzzle_script, address_prefix=h2b("6f"), pay_to_script_prefix=h2b("c4"), bech32_hrp='tb')
testnet_keyparser = KeyParser(
    netcode="XTN", wif_prefix=h2b("ef"), address_prefix=h2b("6f"),
    bip32_prv_prefix=h2b("04358394"), bip32_pub_prefix=h2b("043587CF"), bech32_prefix="tb")


BitcoinTestnet = Network(
    "XTN", "Bitcoin", "testnet3",
    h2b("ef"), h2b("6f"), h2b("c4"), h2b("04358394"), h2b("043587CF"),
    BitcoinTx, BitcoinBlock,
    h2b('0B110907'), 18333, [
        "bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org",
        "bluematt.me", "testnet-seed.bluematt.me"
    ],
    bech32_hrp='tb',
    ui=testnet_ui, keyparser=testnet_keyparser
)
