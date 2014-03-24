import binascii
import struct

from ..serialize.bitcoin_streamer import parse_struct, stream_struct

from .TxIn import TxIn
from .TxOut import TxOut

class Spendable(TxOut):
    def __init__(self, coin_value, script, tx_hash, tx_out_index):
        self.coin_value = int(coin_value)
        self.script = script
        self.tx_hash = tx_hash
        self.tx_out_index = tx_out_index

    def stream(self, f, as_spendable=False):
        self.stream(f)
        if as_spendable:
            stream_struct("#L", f, self.previous_hash, self.previous_index)

    @classmethod
    def parse(class_, f):
        return class_(*parse_struct("QS#L", f))

    def as_dict(self):
        # for use with JSON
        return dict(
            coin_value=self.coin_value,
            script_hex=binascii.hexlify(self.script),
            tx_hash_hex=binascii.hexlify(self.previous_hash),
            tx_out_index=self.previous_index
        )

    @classmethod
    def from_dict(class_, d):
        return class_(d["coin_value"], binascii.unhexlify(d["script_hex"]),
            binascii.unhexlify(d["tx_hash_hex"]), d["tx_out_index"])

    def tx_in(self, script=b'', sequence=4294967295):
        return TxIn(self.tx_hash, self.tx_out_index, script, sequence)
