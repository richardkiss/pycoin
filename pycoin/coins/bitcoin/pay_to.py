from .ScriptTools import BitcoinScriptTools
from pycoin.vm.PayTo import PayTo

_puzzle_script = PayTo(BitcoinScriptTools)


script_for_p2pk = _puzzle_script.script_for_p2pk
script_for_multisig = _puzzle_script.script_for_multisig
script_for_p2pkh = _puzzle_script.script_for_p2pkh
script_for_p2pkh_wit = _puzzle_script.script_for_p2pkh_wit
script_for_nulldata = _puzzle_script.script_for_nulldata
script_for_nulldata_push = _puzzle_script.script_for_nulldata_push
