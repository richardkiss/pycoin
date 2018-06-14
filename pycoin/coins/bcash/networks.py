
from pycoin.serialize import h2b

from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from .Tx import Tx as BcashTx
from ..bitcoin.extras import Extras
from pycoin.block import Block as BcashBlock

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
    wif_prefix=h2b("80"), sec_prefix="BCHSEC:", address_prefix=h2b("00"),
    pay_to_script_prefix=h2b("05"))

mainnet_extras = Extras(BitcoinScriptTools, mainnet_ui)

BcashMainnet = Network(
    'BCH', "Bcash", "mainnet",
    BcashTx, BcashBlock,
    h2b('F9BEB4D9'), 8333, [
        "seed.bitcoinabc.org", "seed-abc.bitcoinforks.org",
        "btccash-seeder.bitcoinunlimited.info", "seed.bitprim.org",
    ],
    ui=mainnet_ui, extras=mainnet_extras
)
