from ..convention import satoshi_to_mbtc
from ..serialize import b2h, b2h_rev, h2b, h2b_rev
from ..serialize.bitcoin_streamer import parse_struct, stream_struct

from .TxIn import TxIn
from .TxOut import TxOut


class Spendable(TxOut):
    def __init__(self, coin_value, script, tx_hash, tx_out_index, block_index_available=0,
                 does_seem_spent=False, block_index_spent=0):
        self.coin_value = int(coin_value)
        self.script = script
        self.tx_hash = tx_hash
        self.tx_out_index = tx_out_index
        self.block_index_available = block_index_available or None
        self.does_seem_spent = bool(does_seem_spent)
        self.block_index_spent = block_index_spent or None

    def stream(self, f, as_spendable=False):
        super(Spendable, self).stream(f)
        if as_spendable:
            stream_struct("#LIbI", f, self.previous_hash, self.previous_index,
                          self.block_index_available, self.does_seem_spent, self.block_index_spent)

    @classmethod
    def parse(class_, f):
        return class_(*parse_struct("QS#LIbI", f))

    def as_dict(self):
        # for use with JSON
        return dict(
            coin_value=self.coin_value,
            script_hex=b2h(self.script),
            tx_hash_hex=b2h(self.tx_hash),
            tx_out_index=self.tx_out_index,
            block_index_available=self.block_index_available,
            does_seem_spent=int(self.does_seem_spent),
            block_index_spent=self.block_index_spent
        )

    @classmethod
    def from_dict(class_, d):
        return class_(d["coin_value"], h2b(d["script_hex"]),
                      h2b(d["tx_hash_hex"]), d["tx_out_index"],
                      d.get("block_index_available"), d.get("does_seem_spent", 0),
                      d.get("block_index_spent"))

    def as_text(self):
        return "/".join([b2h_rev(self.tx_hash), str(self.tx_out_index), b2h(self.script),
                         str(self.coin_value), str(self.block_index_available),
                         "%d" % self.does_seem_spent, str(self.block_index_spent)])

    @classmethod
    def from_text(class_, text):
        the_tuple = (text.split("/") + [0, 0, 0])[:7]
        tx_hash_hex, tx_out_index_str, script_hex, coin_value, \
            block_index_available, does_seem_spent, block_index_spent = the_tuple
        tx_hash = h2b_rev(tx_hash_hex)
        tx_out_index = int(tx_out_index_str)
        script = h2b(script_hex)
        coin_value = int(coin_value)
        return class_(coin_value, script, tx_hash, tx_out_index, block_index_available,
                      bool(does_seem_spent), block_index_spent)

    def tx_in(self, script=b'', sequence=4294967295):
        return TxIn(self.tx_hash, self.tx_out_index, script, sequence)

    def __str__(self):
        return 'Spendable<%s mbtc "%s:%d" %s/%s/%s>' % (
            satoshi_to_mbtc(self.coin_value), b2h_rev(self.tx_hash), self.tx_out_index,
            self.block_index_available, str(self.does_seem_spent)[0], self.block_index_spent)

    def __repr__(self):
        return str(self)
