from pycoin.serialize import h2b

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx

from pycoin.block import Block
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.networks.network import Network
from pycoin.vm.ScriptInfo import ScriptInfo
from pycoin.ui.uiclass import UI

_script_info = ScriptInfo(BitcoinScriptTools)


ltc_ui = UI(
    _script_info, secp256k1_generator,
    bip32_prv_prefix=h2b("019d9cfe"), bip32_pub_prefix=h2b("019da462"),
    wif_prefix=h2b("b0"), sec_prefix="LTCSEC", address_prefix=h2b("30"),
    pay_to_script_prefix=h2b("05"), bech32_hrp='lc')

LitecoinMainnet = Network(
    "LTC", "Litecoin", "mainnet",
    tx=Tx, block=Block,
    ui=ltc_ui
)


xlt_ui = UI(
    _script_info, secp256k1_generator,
    bip32_prv_prefix=h2b("0436ef7d"), bip32_pub_prefix=h2b("0436f6e1"),
    wif_prefix=h2b("ef"), sec_prefix="XLTSEC", address_prefix=h2b("6f"),
    pay_to_script_prefix=h2b("c4"), bech32_hrp='tl')

LitecoinTestnet = Network(
    "XLT", "Litecoin", "testnet",
    tx=Tx, block=Block,
    ui=xlt_ui
)
