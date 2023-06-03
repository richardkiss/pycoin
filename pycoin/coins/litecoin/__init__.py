from pycoin.block import Block
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.satoshi.satoshi_int import parse_satoshi_int
from pycoin.satoshi.satoshi_string import parse_satoshi_string
from pycoin.satoshi.satoshi_struct import parse_struct


class LTCTx(Tx):
    @classmethod
    def parse(class_, f):
        """Parse a Bitcoin transaction Tx.
        :param f: a file-like object that contains a binary streamed transaction
        """
        (version,) = parse_struct("L", f)
        v1 = ord(f.read(1))
        is_segwit = v1 == 0
        has_mweb = False
        if is_segwit:
            flag = ord(f.read(1))
            if flag == 0:
                raise ValueError("bad flag in segwit")
            has_mweb = flag & 0x8 != 0
            is_segwit = flag & 0x1 != 0
            v1 = None
        count = parse_satoshi_int(f, v=v1)
        txs_in = []
        for i in range(count):
            txs_in.append(class_.TxIn.parse(f))
        count = parse_satoshi_int(f)
        txs_out = []
        for i in range(count):
            txs_out.append(class_.TxOut.parse(f))
        if is_segwit:
            for tx_in in txs_in:
                stack = []
                count = parse_satoshi_int(f)
                for i in range(count):
                    stack.append(parse_satoshi_string(f))
                tx_in.witness = stack
        if has_mweb:
            mweb_tx_type = ord(f.read(1))
            if mweb_tx_type:
                # TODO: read serialized MWEB transaction data
                # TODO: save this away
                pass
        (lock_time,) = parse_struct("L", f)
        return class_(version, txs_in, txs_out, lock_time)


class LTCBlock(Block):
    Tx = LTCTx
