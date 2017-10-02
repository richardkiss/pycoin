from pycoin.satoshi import opcodes
from pycoin.satoshi.IntStreamer import IntStreamer
from pycoin.vm.ScriptTools import ScriptTools

from .ScriptStreamer import BitcoinScriptStreamer

BitcoinScriptTools = ScriptTools(opcodes.OPCODE_LIST, IntStreamer, BitcoinScriptStreamer)
