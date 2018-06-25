import io

from pycoin.convention import satoshi_to_mbtc
from pycoin.encoding.hexbytes import b2h, b2h_rev, h2b, h2b_rev
from pycoin.satoshi.satoshi_struct import parse_struct, stream_struct

from .TxIn import TxIn
from .TxOut import TxOut


class Spendable(TxOut):
    TxIn = TxIn

    def __init__(self, coin_value, script, tx_hash, tx_out_index, block_index_available=0,
                 does_seem_spent=False, block_index_spent=0):
        super(Spendable, self).__init__(coin_value, script)
        self.tx_hash = tx_hash
        self.tx_out_index = tx_out_index
        self.block_index_available = block_index_available
        self.does_seem_spent = int(does_seem_spent)
        self.block_index_spent = block_index_spent

    def stream(self, f, as_spendable=False):
        super(Spendable, self).stream(f)
        if as_spendable:
            stream_struct("#LIbI", f, self.previous_hash, self.previous_index,
                          self.block_index_available, bool(self.does_seem_spent), self.block_index_spent)

    @classmethod
    def parse(cls, f):
        return cls(*parse_struct("QS#LIbI", f))

    @classmethod
    def from_bin(cls, blob):
        f = io.BytesIO(blob)
        return cls.parse(f)

    def as_bin(self, as_spendable=False):
        """Return the txo as binary."""
        f = io.BytesIO()
        self.stream(f, as_spendable=as_spendable)
        return f.getvalue()

    def as_dict(self):
        # for use with JSON
        return dict(
            coin_value=self.coin_value,
            script_hex=b2h(self.script),
            tx_hash_hex=b2h_rev(self.tx_hash),
            tx_out_index=self.tx_out_index,
            block_index_available=self.block_index_available,
            does_seem_spent=int(self.does_seem_spent),
            block_index_spent=self.block_index_spent
        )

    @classmethod
    def from_dict(cls, d):
        return cls(d["coin_value"], h2b(d["script_hex"]),
                   h2b_rev(d["tx_hash_hex"]), d["tx_out_index"],
                   d.get("block_index_available", 0), d.get("does_seem_spent", 0),
                   d.get("block_index_spent", 0))

    @classmethod
    def from_tx_out(cls, tx_out, previous_hash, previous_index, block_index_available=0):
        return Spendable(
            tx_out.coin_value, tx_out.script, previous_hash, previous_index, block_index_available)

    def as_text(self):
        return "/".join([b2h_rev(self.tx_hash), str(self.tx_out_index), b2h(self.script),
                         str(self.coin_value), str(self.block_index_available),
                         "%d" % self.does_seem_spent, str(self.block_index_spent)])

    @classmethod
    def from_text(cls, text):
        the_tuple = (text.split("/") + [0, 0, 0])[:7]
        tx_hash_hex, tx_out_index_str, script_hex, coin_value, \
            block_index_available, does_seem_spent, block_index_spent = the_tuple
        tx_hash = h2b_rev(tx_hash_hex)
        tx_out_index = int(tx_out_index_str)
        script = h2b(script_hex)
        coin_value = int(coin_value)
        return cls(coin_value, script, tx_hash, tx_out_index, int(block_index_available),
                   int(does_seem_spent), int(block_index_spent))

    def tx_in(self, script=b'', sequence=4294967295):
        return self.TxIn(self.tx_hash, self.tx_out_index, script, sequence)

    def __str__(self):
        return 'Spendable<%s mbtc "%s:%d" %s/%s/%s>' % (
            satoshi_to_mbtc(self.coin_value), b2h_rev(self.tx_hash), self.tx_out_index,
            self.block_index_available, self.does_seem_spent, self.block_index_spent)

    def __repr__(self):
        return str(self)
