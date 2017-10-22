from pycoin.serialize import h2b

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.coins.bitcoin.KeyParser import KeyParser

from pycoin.block import Block
from pycoin.networks.network import Network
from pycoin.vm.PayTo import PayTo
from pycoin.ui.uiclass import UI

_puzzle_script = PayTo(BitcoinScriptTools)


ltc_ui = UI(_puzzle_script, address_prefix=h2b("30"), pay_to_script_prefix=h2b("05"), bech32_hrp='lc')
ltc_keyparser = KeyParser(
    netcode="LTC", wif_prefix=h2b("b0"), address_prefix=h2b("30"),
    bip32_prv_prefix=h2b("019d9cfe"), bip32_pub_prefix=h2b("019da462"), bech32_prefix=None)

LitecoinMainnet = Network(
    "LTC", "Litecoin", "mainnet",
    b'\xb0', b'\x30', b'\5',
    h2b('019d9cfe'), h2b('019da462'),
    tx=Tx, block=Block,
    bech32_hrp='lc',
    ui=ltc_ui, keyparser=ltc_keyparser
)


xlt_ui = UI(_puzzle_script, address_prefix=h2b("6f"), pay_to_script_prefix=h2b("c4"), bech32_hrp='tl')
xlt_keyparser = KeyParser(
    netcode="XLT", wif_prefix=h2b("ef"), address_prefix=h2b("6f"),
    bip32_prv_prefix=h2b("0436ef7d"), bip32_pub_prefix=h2b("0436f6e1"), bech32_prefix=None)

LitecoinTestnet = Network(
    "XLT", "Litecoin", "testnet",
    b'\xef', b'\x6f', b'\xc4',
    h2b('0436ef7d'), h2b('0436f6e1'),
    tx=Tx, block=Block,
    bech32_hrp='tl',
    ui=xlt_ui, keyparser=xlt_keyparser
)
