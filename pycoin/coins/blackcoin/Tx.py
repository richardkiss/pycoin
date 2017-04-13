from pycoin.serialize.bitcoin_streamer import (
    parse_struct, parse_bc_int, parse_bc_string,
    stream_struct, stream_bc_string
)
from pycoin.tx.Tx import Tx as BaseTx


class Tx(BaseTx):
    """
    A transaction for Proof-of-Stake (at least for altcoins derived from PPCoin??):
       - has an extra signature over the block (see block.py), appended after
         the array of transactions.
       - has nTime value inserted after version number of txn, before vin array
    """

    ALLOW_SEGWIT = False

    @classmethod
    def parse(class_, f, allow_segwit=None):
        """Parse a Bitcoin transaction Tx from the file-like object f."""
        if allow_segwit is None:
            allow_segwit = class_.ALLOW_SEGWIT
        txs_in = []
        txs_out = []
        version, mined_time = parse_struct("LL", f)
        v1 = ord(f.read(1))
        is_segwit = allow_segwit and (v1 == 0)
        v2 = None
        if is_segwit:
            flag = f.read(1)
            if flag == b'\0':
                raise ValueError("bad flag in segwit")
            if flag == b'\1':
                v1 = None
            else:
                is_segwit = False
                v2 = ord(flag)
        count = parse_bc_int(f, v=v1)
        txs_in = []
        for i in range(count):
            txs_in.append(class_.TxIn.parse(f))
        count = parse_bc_int(f, v=v2)
        txs_out = []
        for i in range(count):
            txs_out.append(class_.TxOut.parse(f))

        if is_segwit:
            for tx_in in txs_in:
                stack = []
                count = parse_bc_int(f)
                for i in range(count):
                    stack.append(parse_bc_string(f))
                tx_in.witness = stack
        lock_time, = parse_struct("L", f)
        return class_(version, mined_time, txs_in, txs_out, lock_time)

    def __init__(self, version, mined_time, txs_in, txs_out, lock_time=0, unspents=None):
        super(Tx, self).__init__(version, txs_in, txs_out, lock_time, unspents=unspents)
        self.mined_time = mined_time

    def stream(self, f, blank_solutions=False, include_unspents=False, include_witness_data=True):
        """Stream a Bitcoin transaction Tx to the file-like object f."""
        include_witnesses = include_witness_data and self.has_witness_data()
        stream_struct("LL", f, self.version, self.mined_time)
        if include_witnesses:
            f.write(b'\0\1')
        stream_struct("I", f, len(self.txs_in))
        for t in self.txs_in:
            t.stream(f, blank_solutions=blank_solutions)
        stream_struct("I", f, len(self.txs_out))
        for t in self.txs_out:
            t.stream(f)
        if include_witnesses:
            for tx_in in self.txs_in:
                witness = tx_in.witness
                stream_struct("I", f, len(witness))
                for w in witness:
                    stream_bc_string(f, w)
        stream_struct("L", f, self.lock_time)
        if include_unspents and not self.missing_unspents():
            self.stream_unspents(f)
