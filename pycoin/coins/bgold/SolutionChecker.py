from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.encoding.hash import double_sha256
from pycoin.satoshi.flags import SIGHASH_FORKID

from ..bitcoin.SolutionChecker import BitcoinSolutionChecker


class BgoldSolutionChecker(BitcoinSolutionChecker):

    FORKID_BTG = 79  # atomic number for Au (gold)

    def _signature_hash(self, tx_out_script, unsigned_txs_out_idx, hash_type):
        """
        Return the canonical hash for a transaction. We need to
        remove references to the signature, since it's a signature
        of the hash before the signature is applied.

        tx_out_script: the script the coins for unsigned_txs_out_idx are coming from
        unsigned_txs_out_idx: where to put the tx_out_script
        hash_type: one of SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL,
        optionally bitwise or'ed with SIGHASH_ANYONECANPAY
        """

        if hash_type & SIGHASH_FORKID != SIGHASH_FORKID:
            raise self.ScriptError()

        return self._signature_for_hash_type_segwit(tx_out_script, unsigned_txs_out_idx, hash_type)

    def _signature_for_hash_type_segwit(self, script, tx_in_idx, hash_type):
        hash_type |= self.FORKID_BTG << 8
        return from_bytes_32(double_sha256(self._segwit_signature_preimage(script, tx_in_idx, hash_type)))
