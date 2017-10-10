from pycoin.serialize import h2b

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx

from pycoin.block import Block
from pycoin.networks.network import Network
from pycoin.vm.PuzzleScripts import PuzzleScripts
from pycoin.ui.uiclass import UI

_puzzle_script = PuzzleScripts(BitcoinScriptTools)


ltc_ui = UI(_puzzle_script, address_prefix=h2b("30"), pay_to_script_prefix=h2b("05"), bech32_hrp='lc')

LitecoinMainnet = Network(
    "LTC", "Litecoin", "mainnet",
    b'\xb0', b'\x30', b'\5',
    h2b('019d9cfe'), h2b('019da462'),
    tx=Tx, block=Block,
    bech32_hrp='lc',
    ui=ltc_ui
)


xlt_ui = UI(_puzzle_script, address_prefix=h2b("6f"), pay_to_script_prefix=h2b("c4"), bech32_hrp='tl')

LitecoinTestnet = Network(
    "XLT", "Litecoin", "testnet",
    b'\xef', b'\x6f', b'\xc4',
    h2b('0436ef7d'), h2b('0436f6e1'),
    tx=Tx, block=Block,
    bech32_hrp='tl',
    ui=xlt_ui
)
