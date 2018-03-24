

from pycoin.contrib.who_signed import WhoSigned
from pycoin.vm.annotate import Annotate


class Extras(object):
    def __init__(self, script_tools, ui):
        self.annotate = Annotate(script_tools, ui)
        self.Key = ui._key_class
        self.BIP32Node = ui._bip32node_class
        self.ElectrumKey = ui._electrum_class
        who_signed = WhoSigned(script_tools)
        self.who_signed_tx = who_signed.who_signed_tx
        self.public_pairs_signed = who_signed.public_pairs_signed
        self.extract_secs = who_signed.extract_secs
        self.extract_signatures = who_signed.extract_signatures
        self.public_pairs_for_script = who_signed.public_pairs_for_script
        self.ScriptTools = script_tools
