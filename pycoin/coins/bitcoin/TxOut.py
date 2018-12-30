from .ScriptTools import BitcoinScriptTools  # BRAIN DAMAGE
from ...convention import satoshi_to_mbtc

from pycoin.satoshi.satoshi_struct import parse_struct, stream_struct


class TxOut(object):

    COIN_VALUE_CAST_F = int

    """
    The part of a Tx that specifies where the Bitcoin goes to.
    """

    def __init__(self, coin_value, script):
        assert isinstance(script, bytes)
        self.coin_value = self.COIN_VALUE_CAST_F(coin_value)
        self.script = script

    def stream(self, f):
        stream_struct("QS", f, self.coin_value, self.script)

    @classmethod
    def parse(cls, f):
        return cls(*parse_struct("QS", f))

    def __str__(self):
        return '%s<%s mbtc "%s">' % (
            self.__class__.__name__,
            satoshi_to_mbtc(self.coin_value),
            BitcoinScriptTools.disassemble(self.script)
        )

    def puzzle_script(self):
        return self.script


"""
The MIT License (MIT)

Copyright (c) 2013 by Richard Kiss

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
