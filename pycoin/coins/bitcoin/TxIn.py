from __future__ import annotations

from typing import Any, IO

from pycoin.encoding.hash import hash160
from pycoin.encoding.hexbytes import b2h, b2h_rev, h2b
from pycoin.satoshi.satoshi_struct import parse_struct, stream_struct

from .ScriptTools import BitcoinScriptTools as ScriptTools  # BRAIN DAMAGE


ZERO = b"\0" * 32


class TxIn:
    """
    The part of a Tx that specifies where the Bitcoin comes from.
    """

    def __init__(self, previous_hash: bytes, previous_index: int, script: bytes = b"", sequence: int = 4294967295) -> None:
        self.previous_hash = previous_hash
        self.previous_index = previous_index
        self.script = script
        self.sequence = sequence
        self.witness: list[bytes] = []

    @classmethod
    def coinbase_tx_in(class_, script: bytes) -> TxIn:
        tx = class_(previous_hash=ZERO, previous_index=4294967295, script=script)
        return tx

    def stream(self, f: IO[bytes], blank_solutions: bool = False) -> None:
        script = b"" if blank_solutions else self.script
        stream_struct(
            "#LSL", f, self.previous_hash, self.previous_index, script, self.sequence
        )

    @classmethod
    def parse(cls, f: IO[bytes]) -> TxIn:
        return cls(*parse_struct("#LSL", f))

    def is_coinbase(self) -> bool:
        return self.previous_hash == ZERO

    def public_key_sec(self) -> bytes | None:
        """Return the public key as sec, or None in case of failure."""
        if self.is_coinbase():
            return None
        opcodes = ScriptTools.opcode_list(self.script)
        if len(opcodes) == 2 and opcodes[0].startswith("[30"):
            sec = h2b(opcodes[1][1:-1])
            return sec
        return None

    def address(self, address_api: Any) -> str:
        if self.is_coinbase():
            return "(coinbase)"
        sec = self.public_key_sec()
        if sec:
            address: str = address_api.for_p2pkh(hash160(sec))
            return address
        return "(unknown)"

    def __str__(self) -> str:
        if self.is_coinbase():
            return "TxIn<COINBASE: %s>" % b2h(self.script)
        return 'TxIn<%s[%d] "%s">' % (
            b2h_rev(self.previous_hash),
            self.previous_index,
            ScriptTools.disassemble(self.script),
        )


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
