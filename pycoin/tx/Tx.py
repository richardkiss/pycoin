# -*- coding: utf-8 -*-
"""
Parse, stream, create, sign and verify Bitcoin transactions as Tx structures.


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

import io

from ..ecdsa import generator_secp256k1, public_pair_for_secret_exponent
from ..encoding import bitcoin_address_to_ripemd160_sha256_sec, double_sha256, public_pair_to_ripemd160_sha256_sec
from ..serialize import b2h, b2h_rev
from ..serialize.bitcoin_streamer import parse_struct, stream_struct

from .TxIn import TxIn, TxInGeneration
from .TxOut import TxOut

from .script.tools import compile
from .script.signing import sign_signature
from .script.vm import verify_script

class ValidationFailureError(Exception): pass

class Tx(object):
    @classmethod
    def coinbase_tx(class_, public_key_sec, coin_value, coinbase_bytes=b''):
        """Create a special "first in block" transaction that includes the bonus for mining and transaction fees."""
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
    def standard_tx(class_, previous_hash_index__tuple_list, coin_value__bitcoin_address__tuple_list, tx_db=None, secret_exponent_for_public_pair_lookup=None):
        """Create a standard transaction.
        previous_hash_index__tuple_list: a list of pairs of the form (previous
          hash, previous index) corresponding to the source coins. You must
          have private keys for these incoming transactions.
        coin_value__bitcoin_address__tuple_list: a list of pairs of the
          form (satoshi_count, bitcoin_address) corresponding to the payees.
          The satoshi_count is an integer indicating number of Satoshis (there
          are 1e8 Satoshis in a Bitcoin) and bitcoin_address is a standard
          Bitcoin address like 1FKYxGDywd7giFbnmKdvYmVgBHB9B2HXMw.

        If you want the transaction to be signed, you must also pass in tx_db
        and secret_exponent_for_public_pair_lookup parameters. See the documentation
        in the "sign" method.
        """
        tx_in_list = [TxIn(h, idx) for h, idx in previous_hash_index__tuple_list]
        tx_out_list = []
        STANDARD_SCRIPT_OUT = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG"
        for coin_value, bitcoin_address in coin_value__bitcoin_address__tuple_list:
            ripemd160_sha256 = bitcoin_address_to_ripemd160_sha256_sec(bitcoin_address)
            script_text = STANDARD_SCRIPT_OUT % b2h(ripemd160_sha256)
            script_bin = compile(script_text)
            tx_out_list.append(TxOut(coin_value, script_bin))
        # TODO: what is this?
        version = 1
        # TODO: what is this?
        lock_timestamp = 0
        tx = Tx(version, tx_in_list, tx_out_list, lock_timestamp)
        if tx_db and secret_exponent_for_public_pair_lookup:
            tx = tx.sign(tx_db, secret_exponent_for_public_pair_lookup)
        return tx

    @classmethod
    def parse(self, f, is_first_in_block=False):
        """Parse a Bitcoin transaction Tx from the file-like object f."""
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
        """Stream a Bitcoin transaction Tx to the file-like object f."""
        stream_struct("LI", f, self.version, len(self.txs_in))
        for t in self.txs_in:
            t.stream(f)
        stream_struct("I", f, len(self.txs_out))
        for t in self.txs_out:
            t.stream(f)
        stream_struct("L", f, self.lock_timestamp)

    def hash(self):
        """Return the hash for this Tx object."""
        s = io.BytesIO()
        self.stream(s)
        return double_sha256(s.getvalue())

    def id(self):
        """Return the human-readable hash for this Tx object."""
        return b2h_rev(self.hash())

    def validate(self, tx_db):
        """Checks the transaction Tx signatures for validity. If invalid, raises a ValidationFailureError."""
        for idx, tx_in in enumerate(self.txs_in):
            tx_from = tx_db.get(tx_in.previous_hash)
            if not tx_from:
                raise ValidationFailureError("missing source transaction %s" % b2h_rev(tx_in.previous_hash))
            if tx_in.previous_hash != tx_from.hash():
                raise ValidationFailureError("source transaction %s has incorrect hash (actually %s)" % (b2h_rev(tx_in.previous_hash), b2h_rev(tx_from.hash())))
            tx_out = tx_from.txs_out[tx_in.previous_index]
            if not verify_script(tx_in.script, tx_out.script, self, idx):
                raise ValidationFailureError("Tx %s TxIn index %d script did not verify" % (b2h_rev(tx_in.previous_hash), idx))

    def sign(self, tx_db, secret_exponents, public_pair_compressed_for_ripemd160_sha256_lookup=None):
        """Sign a standard transaction.
        tx_db:
            a dictionary-like object that returns the Tx corresponding to the
            key Tx.hash(). We need this to find the old transaction so we can
            create a signature closing it out. Do something like this:
                tx_db = dict((tx.hash(), tx) for tx in transaction_list)
        secret_exponents:
            either an array of the relevant secret exponents OR
            a dictionary-like object that returns a secret_exponent for a public_pair.
            Do something like this:
               sefppl = dict(((public_pair_for_secret_exponent(generator_secp256k1, secret_exponent)) :
                   secret_exponent) for secret_exponent in secret_exponent_list)
        public_pair_compressed_for_ripemd160_sha256_lookup:
            an optional dictionary-like object that returns a tuple (public_pair, compressed) for the
            key public_pair_to_ripemd160_sha256_sec(public_pair, compressed=compressed)
            If this parameter is not included, it is generated by the list of secret exponents. However,
            if this list is long, it may take a long time.
        """

        # if secret_exponents is a list, we generate the lookup
        # build secret_exponent_for_public_pair_lookup

        if hasattr(secret_exponents, "get"):
            secret_exponent_for_public_pair_lookup = secret_exponents
        else:
            secret_exponent_for_public_pair_lookup = {}
            public_pair_compressed_for_ripemd160_sha256_lookup = {}
            for secret_exponent in secret_exponents:
                public_pair = public_pair_for_secret_exponent(generator_secp256k1, secret_exponent)
                secret_exponent_for_public_pair_lookup[public_pair] = secret_exponent
                public_pair_compressed_for_ripemd160_sha256_lookup[public_pair_to_ripemd160_sha256_sec(public_pair, compressed=True)] = (public_pair, True)
                public_pair_compressed_for_ripemd160_sha256_lookup[public_pair_to_ripemd160_sha256_sec(public_pair, compressed=False)] = (public_pair, False)

        new_txs_in = []
        for tx_in in self.txs_in:
            tx_from = tx_db.get(tx_in.previous_hash)
            new_script = sign_signature(tx_from, self, tx_in.previous_index, secret_exponent_for_public_pair_lookup.get, public_pair_compressed_for_ripemd160_sha256_lookup.get)
            if not new_script: raise Exception("bad signature")
            new_txs_in.append(TxIn(tx_in.previous_hash, tx_in.previous_index, new_script))
        tx = Tx(self.version, new_txs_in, self.txs_out, self.lock_timestamp)
        tx.validate(tx_db)
        return tx

    def __str__(self):
        return "Tx [%s]" % self.id()

    def __repr__(self):
        return "Tx [%s] (v:%d) [%s] [%s]" % (self.id(), self.version, ", ".join(str(t) for t in self.txs_in), ", ".join(str(t) for t in self.txs_out))
