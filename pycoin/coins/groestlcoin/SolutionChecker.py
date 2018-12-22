import io

from .hash import sha256
from pycoin.coins.bitcoin.SegwitChecker import ZERO32
from pycoin.coins.bitcoin.SolutionChecker import BitcoinSolutionChecker
from pycoin.encoding.bytes32 import from_bytes_32

from pycoin.satoshi.satoshi_struct import stream_struct

from pycoin.satoshi.flags import (
    SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
)


class GroestlcoinSolutionChecker(BitcoinSolutionChecker):
    def _hash_prevouts(self, hash_type):
        if hash_type & SIGHASH_ANYONECANPAY:
            return ZERO32
        f = io.BytesIO()
        for tx_in in self.tx.txs_in:
            f.write(tx_in.previous_hash)
            stream_struct("L", f, tx_in.previous_index)
        return sha256(f.getvalue())

    def _hash_sequence(self, hash_type):
        if (
                (hash_type & SIGHASH_ANYONECANPAY) or
                ((hash_type & 0x1f) == SIGHASH_SINGLE) or
                ((hash_type & 0x1f) == SIGHASH_NONE)
        ):
            return ZERO32

        f = io.BytesIO()
        for tx_in in self.tx.txs_in:
            stream_struct("L", f, tx_in.sequence)
        return sha256(f.getvalue())

    def _hash_outputs(self, hash_type, tx_in_idx):
        txs_out = self.tx.txs_out
        if hash_type & 0x1f == SIGHASH_SINGLE:
            if tx_in_idx >= len(txs_out):
                return ZERO32
            txs_out = txs_out[tx_in_idx:tx_in_idx+1]
        elif hash_type & 0x1f == SIGHASH_NONE:
            return ZERO32
        f = io.BytesIO()
        for tx_out in txs_out:
            stream_struct("QS", f, tx_out.coin_value, tx_out.script)
        return sha256(f.getvalue())

    def _signature_for_hash_type_segwit(self, script, tx_in_idx, hash_type):
        return from_bytes_32(sha256(self._segwit_signature_preimage(script, tx_in_idx, hash_type)))
