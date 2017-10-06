from .ScriptTools import BitcoinScriptTools
from pycoin.vm.PuzzleScripts import PuzzleScripts

_puzzle_script = PuzzleScripts(BitcoinScriptTools)


script_for_p2pk = _puzzle_script.script_for_p2pk
script_for_multisig = _puzzle_script.script_for_multisig
script_for_p2pkh = _puzzle_script.script_for_p2pkh
script_for_p2pkh_wit = _puzzle_script.script_for_p2pkh_wit
#script_for_p2sh(underlying_script_hash160):
#script_for_p2s = _puzzle_script.script_for_p2s
#script_for_p2sh_wit(underlying_script):
#script_for_multisig(m, sec_keys):
script_for_nulldata = _puzzle_script.script_for_nulldata
script_for_nulldata_push = _puzzle_script.script_for_nulldata_push
