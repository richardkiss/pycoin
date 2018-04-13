from pycoin.serialize import h2b

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx

from pycoin.block import Block
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.networks.network import Network
from pycoin.vm.ScriptInfo import ScriptInfo
from pycoin.ui.uiclass import UI

_script_info = ScriptInfo(BitcoinScriptTools)


mona_ui = UI(
    _script_info, secp256k1_generator,
    bip32_prv_prefix=h2b("0488ade4"), bip32_pub_prefix=h2b("0488b21e"),
    wif_prefix=h2b("b0"), sec_prefix="MONASEC", address_prefix=h2b("32"),
    pay_to_script_prefix=h2b("37"), bech32_hrp='mona')

MonacoinMainnet = Network(
    "MONA", "Monacoin", "mainnet",
    tx=Tx, block=Block,
    ui=mona_ui
)


tmona_ui = UI(
    _script_info, secp256k1_generator,
    bip32_prv_prefix=h2b("04358394"), bip32_pub_prefix=h2b("043587cf"),
    wif_prefix=h2b("ef"), sec_prefix="TMONASEC", address_prefix=h2b("6f"),
    pay_to_script_prefix=h2b("75"), bech32_hrp='tmona')

MonacoinTestnet = Network(
    "TMONA", "Monacoin", "testnet",
    tx=Tx, block=Block,
    ui=tmona_ui
)
