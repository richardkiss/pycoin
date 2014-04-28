import binascii

from ..convention import satoshi_to_mbtc
from ..serialize import b2h, b2h_rev, h2b_rev
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
        super(Spendable, self).stream(f)
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
            tx_hash_hex=binascii.hexlify(self.tx_hash),
            tx_out_index=self.tx_out_index
        )

    @classmethod
    def from_dict(class_, d):
        return class_(d["coin_value"], binascii.unhexlify(d["script_hex"]),
                      binascii.unhexlify(d["tx_hash_hex"]), d["tx_out_index"])

    def as_text(self):
        return "/".join([b2h_rev(self.tx_hash), str(self.tx_out_index),
                         b2h(self.script), str(self.coin_value)])

    @classmethod
    def from_text(class_, text):
        tx_hash_hex, tx_out_index_str, script_hex, coin_value = text.split("/")
        tx_hash = h2b_rev(tx_hash_hex)
        tx_out_index = int(tx_out_index_str)
        script = binascii.unhexlify(script_hex)
        coin_value = int(coin_value)
        return class_(coin_value, script, tx_hash, tx_out_index)

    def tx_in(self, script=b'', sequence=4294967295):
        return TxIn(self.tx_hash, self.tx_out_index, script, sequence)

    def __str__(self):
        return 'Spendable<%s mbtc "%s:%d">' % (
            satoshi_to_mbtc(self.coin_value), b2h_rev(self.tx_hash), self.tx_out_index)

    def __repr__(self):
        return str(self)
