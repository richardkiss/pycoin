
import decimal
import logging

import io

from ..serialize.bitcoin_streamer import parse_struct, stream_struct
from ..serialize import b2h, b2h_rev
from ..encoding import bitcoin_address_to_ripemd160_sha_sec, double_sha256, public_pair_to_ripemd160_sha_sec
from .script.tools import disassemble, compile
from .script.signing import sign_signature
from .script.vm import verify_script
from .. import ecdsa

COIN_FACTOR = decimal.Decimal(100000000)

class ValidationFailureError(Exception): pass

class TxIn(object):
    """
    The part of a Tx that specifies where the BitCoin comes from.
    """
    def __init__(self, previous_hash, previous_index, script=b'', sequence=4294967295):
        self.previous_hash = previous_hash
        self.previous_index = previous_index
        self.script = script
        self.sequence = sequence

    def stream(self, f):
        stream_struct("#LSL", f, self.previous_hash, self.previous_index, self.script, self.sequence)

    @classmethod
    def parse(self, f):
        return self(*parse_struct("#LSL", f))

    def __str__(self):
        return 'TxIn<%s[%d] "%s">' % (b2h_rev(self.previous_hash), self.previous_index, disassemble(self.script))

class TxInGeneration(TxIn):
    def __str__(self):
        return 'TxIn<COINBASE: %s>' % b2h(self.script)

class TxOut(object):
    """
    The part of a Tx that specifies where the BitCoin goes to.
    """
    def __init__(self, coin_value, script):
        self.coin_value = int(coin_value)
        self.script = script

    def stream(self, f):
        stream_struct("QS", f, self.coin_value, self.script)

    @classmethod
    def parse(self, f):
        return self(*parse_struct("QS", f))

    def __str__(self):
        return 'TxOut<%s "%s">' % (decimal.Decimal(self.coin_value)/COIN_FACTOR, disassemble(self.script))

class Tx(object):

    @classmethod
    def coinbase_tx(class_, public_key_sec, coin_value, coinbase_bytes=b''):
        tx_in = TxInGeneration(previous_hash=bytes([0] * 32), previous_index=(1<<32)-1, script=coinbase_bytes)
        COINBASE_SCRIPT_OUT = "%s OP_CHECKSIG"
        script_text = COINBASE_SCRIPT_OUT % b2h(public_key_sec)
        script_bin = compile(script_text)
        tx_out = TxOut(coin_value, script_bin)
        # TODO: what is this?
        version = 1
        # TODO: what is this?
        lock_timestamp = 0
        return class_(version, [tx_in], [tx_out], lock_timestamp)

    @classmethod
    def standard_tx(class_, previous_hash_index__tuple_list, coin_value__bitcoin_address__tuple_list, tx_db=None, secret_exponent_key_for_public_pair_lookup=None):
        # TODO: what is this?
        version = 1
        # TODO: what is this?
        lock_timestamp = 0
        tx_in_list = [TxIn(h, idx) for h, idx in previous_hash_index__tuple_list]
        tx_out_list = []
        STANDARD_SCRIPT_OUT = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG"
        for coin_value, bitcoin_address in coin_value__bitcoin_address__tuple_list:
            ripemd160_sha = bitcoin_address_to_ripemd160_sha_sec(bitcoin_address)
            script_text = STANDARD_SCRIPT_OUT % b2h(ripemd160_sha)
            script_bin = compile(script_text)
            tx_out_list.append(TxOut(coin_value, script_bin))
        tx = Tx(version, tx_in_list, tx_out_list, lock_timestamp)
        if tx_db and secret_exponent_key_for_public_pair_lookup:
            tx = tx.sign(tx_db, secret_exponent_key_for_public_pair_lookup)
        return tx

    @classmethod
    def parse(self, f, is_first_in_block=False):
        version, count = parse_struct("LI", f)
        txs_in = []
        if is_first_in_block:
            txs_in.append(TxInGeneration.parse(f))
            count = count - 1
        for i in range(count):
            txs_in.append(TxIn.parse(f))
        count, = parse_struct("I", f)
        txs_out = []
        for i in range(count):
            txs_out.append(TxOut.parse(f))
        lock_timestamp, = parse_struct("L", f)
        return self(version, txs_in, txs_out, lock_timestamp)

    def __init__(self, version, txs_in, txs_out, lock_timestamp=0):
        self.version = version
        self.txs_in = txs_in
        self.txs_out = txs_out
        self.lock_timestamp = lock_timestamp

    def stream(self, f):
        stream_struct("LI", f, self.version, len(self.txs_in))
        for t in self.txs_in:
            t.stream(f)
        stream_struct("I", f, len(self.txs_out))
        for t in self.txs_out:
            t.stream(f)
        stream_struct("L", f, self.lock_timestamp)

    def hash(self):
        s = io.BytesIO()
        self.stream(s)
        return double_sha256(s.getvalue())

    def id(self):
        return b2h_rev(self.hash())

    def validate(self, tx_db):
        for idx, tx_in in enumerate(self.txs_in):
            tx_from = tx_db.get(tx_in.previous_hash)
            if not tx_from:
                raise ValidationFailureError("missing source transaction %s" % b2h_rev(tx_in.previous_hash))
            if tx_in.previous_hash != tx_from.hash():
                raise ValidationFailureError("source transaction %s has incorrect hash (actually %s)" % (b2h_rev(tx_in.previous_hash), b2h_rev(tx_from.hash())))
            tx_out = tx_from.txs_out[tx_in.previous_index]
            if not verify_script(tx_in.script, tx_out.script, self, idx):
                raise ValidationFailureError("Tx %s TxIn index %d did not verify" % (b2h_rev(tx_in.previous_hash), idx))

    def sign(self, tx_db, secret_exponents, public_pair_compressed_for_ripemd160_sha_key_lookup=None):
        # if secret_exponents is a list, we generate the lookup
        # build secret_exponent_key_for_public_pair_lookup
        if hasattr(secret_exponents, "get"):
            secret_exponent_key_for_public_pair_lookup = secret_exponents
        else:
            secret_exponent_key_for_public_pair_lookup = {}
            public_pair_compressed_for_ripemd160_sha_key_lookup = {}
            for secret_exponent in secret_exponents:
                public_pair = ecdsa.public_pair_for_secret_exponent(ecdsa.generator_secp256k1, secret_exponent)
                secret_exponent_key_for_public_pair_lookup[public_pair] = secret_exponent
                public_pair_compressed_for_ripemd160_sha_key_lookup[public_pair_to_ripemd160_sha_sec(public_pair, compressed=True)] = (public_pair, True)
                public_pair_compressed_for_ripemd160_sha_key_lookup[public_pair_to_ripemd160_sha_sec(public_pair, compressed=False)] = (public_pair, False)

        new_txs_in = []
        for tx_in in self.txs_in:
            tx_from = tx_db.get(tx_in.previous_hash)
            new_script = sign_signature(tx_from, self, tx_in.previous_index, secret_exponent_key_for_public_pair_lookup.get, public_pair_compressed_for_ripemd160_sha_key_lookup.get)
            if not new_script: raise Exception("bad signature")
            new_txs_in.append(TxIn(tx_in.previous_hash, tx_in.previous_index, new_script))
        tx = Tx(self.version, new_txs_in, self.txs_out, self.lock_timestamp)
        tx.validate(tx_db)
        return tx

    def __str__(self):
        return "Tx [%s]" % self.id()

    def __repr__(self):
        return "Tx [%s] (v:%d) [%s] [%s]" % (self.id(), self.version, ", ".join(str(t) for t in self.txs_in), ", ".join(str(t) for t in self.txs_out))
