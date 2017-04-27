from ...tx.script import opcodes

from ...tx.script.IntStreamer import IntStreamer
from ...tx.script.ScriptTools import ScriptTools

from .ScriptCodec import BitcoinScriptCodec

BitcoinScriptTools = ScriptTools(opcodes.OPCODE_LIST, IntStreamer, BitcoinScriptCodec)
