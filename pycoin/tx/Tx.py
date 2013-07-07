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
from ..encoding import bitcoin_address_to_hash160_sec, double_sha256, from_bytes_32, public_pair_to_hash160_sec
from ..serialize import b2h, b2h_rev
from ..serialize.bitcoin_streamer import parse_struct, stream_struct

from .TxIn import TxIn, TxInGeneration
from .TxOut import TxOut

from .script import opcodes
from .script import tools
from .script.signing import solver
from .script.vm import verify_script

class ValidationFailureError(Exception): pass

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

class Tx(object):
    @classmethod
    def coinbase_tx(class_, public_key_sec, coin_value, coinbase_bytes=b''):
        """Create a special "first in block" transaction that includes the bonus for mining and transaction fees."""
        tx_in = TxInGeneration(previous_hash=(b'\0' * 32), previous_index=(1<<32)-1, script=coinbase_bytes)
        COINBASE_SCRIPT_OUT = "%s OP_CHECKSIG"
        script_text = COINBASE_SCRIPT_OUT % b2h(public_key_sec)
        script_bin = tools.compile(script_text)
        tx_out = TxOut(coin_value, script_bin)
        # TODO: what is this?
        version = 1
        # TODO: what is this?
        lock_timestamp = 0
        return class_(version, [tx_in], [tx_out], lock_timestamp)

    @classmethod
    def standard_tx(class_, previous_hash_index__tuple_list, coin_value__bitcoin_address__tuple_list, tx_out_script_db=None, secret_exponent_for_public_pair_lookup=None):
        """Create a standard transaction.
        previous_hash_index__tuple_list: a list of pairs of the form (previous
          hash, previous index) corresponding to the source coins. You must
          have private keys for these incoming transactions.
        coin_value__bitcoin_address__tuple_list: a list of pairs of the
          form (satoshi_count, bitcoin_address) corresponding to the payees.
          The satoshi_count is an integer indicating number of Satoshis (there
          are 1e8 Satoshis in a Bitcoin) and bitcoin_address is a standard
          Bitcoin address like 1FKYxGDywd7giFbnmKdvYmVgBHB9B2HXMw.

        If you want the transaction to be signed, you must also pass in tx_out_script_db
        and secret_exponent_for_public_pair_lookup parameters. See the documentation
        in the "sign" method.
        """
        tx_in_list = [TxIn(h, idx) for h, idx in previous_hash_index__tuple_list]
        tx_out_list = []
        STANDARD_SCRIPT_OUT = "OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG"
        for coin_value, bitcoin_address in coin_value__bitcoin_address__tuple_list:
            hash160 = bitcoin_address_to_hash160_sec(bitcoin_address)
            script_text = STANDARD_SCRIPT_OUT % b2h(hash160)
            script_bin = tools.compile(script_text)
            tx_out_list.append(TxOut(coin_value, script_bin))
        # TODO: what is this?
        version = 1
        # TODO: what is this?
        lock_timestamp = 0
        tx = Tx(version, tx_in_list, tx_out_list, lock_timestamp)
        if tx_out_script_db and secret_exponent_for_public_pair_lookup:
            tx = tx.sign(tx_out_script_db, secret_exponent_for_public_pair_lookup)
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

    def clone(self):
        """Return a copy."""
        s = io.BytesIO()
        self.stream(s)
        return self.parse(io.BytesIO(s.getvalue()))

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

    def hash(self, signature_type=None):
        """Return the hash for this Tx object."""
        s = io.BytesIO()
        self.stream(s)
        if signature_type:
            stream_struct("L", s, signature_type)
        return double_sha256(s.getvalue())

    def id(self):
        """Return the human-readable hash for this Tx object."""
        return b2h_rev(self.hash())

    def partial_hash(self, tx_out_script, tx_in_idx, signature_type):
        """Return the canonical hash for a transaction. We need to
        remove references to the signature, since it's a signature
        of the hash before the signature is applied.

        tx_out_script: the script the coins for tx_in_idx are coming from
        tx_in_idx: where to put the tx_out_script
        signature_type: always seems to be SIGHASH_ALL
        """

        # first off, make a copy
        tx_tmp = self.clone()

        # In case concatenating two scripts ends up with two codeseparators,
        # or an extra one at the end, this prevents all those possible incompatibilities.
        tx_out_script = tools.delete_subscript(tx_out_script, [opcodes.OP_CODESEPARATOR])

        # blank out other inputs' signatures
        for i in range(len(tx_tmp.txs_in)):
            tx_tmp.txs_in[i].script = b''
        tx_tmp.txs_in[tx_in_idx].script = tx_out_script

        # Blank out some of the outputs
        if (signature_type & 0x1f) == SIGHASH_NONE:
            # Wildcard payee
            tx_tmp.txs_out = []

            # Let the others update at will
            for i in range(len(tx_tmp.txs_in)):
                if i != tx_in_idx:
                    tx_tmp.txs_in[i].sequence = 0

        elif (signature_type & 0x1f) == SIGHASH_SINGLE:
            # Only lockin the txout payee at same index as txin
            n_out = tx_in_idx
            for i in range(n_out):
                tx_tmp.txs_out[i].coin_value = -1
                tx_tmp.txs_out[i].script = ''

            # Let the others update at will
            for i in range(len(tx_tmp.txs_in)):
                if i != tx_in_idx:
                    tx_tmp.txs_in[i].sequence = 0

        # Blank out other inputs completely, not recommended for open transactions
        if signature_type & SIGHASH_ANYONECANPAY:
            tx_tmp.txs_in = [tx_tmp.txs_in[tx_in_idx]]

        return from_bytes_32(tx_tmp.hash(signature_type=signature_type))

    def validate(self, tx_out_script_db):
        """Checks the transaction Tx signatures for validity. If invalid, raises a ValidationFailureError.
        tx_out_script_db: lookup of (hash, idx) => output script"""
        for tx_in_idx, tx_in in enumerate(self.txs_in):
            tx_out_script = tx_out_script_db.get((tx_in.previous_hash, tx_in.previous_index))
            if tx_out_script is None:
                raise ValidationFailureError("can't find source tx_out script for %s" % tx_in)
            partial_hash = self.partial_hash(tx_out_script, tx_in_idx, signature_type=SIGHASH_ALL)
            if not verify_script(tx_in.script, tx_out_script, partial_hash, hash_type=0):
                raise ValidationFailureError("Tx %s TxIn index %d script did not verify" % (b2h_rev(tx_in.previous_hash), tx_in_idx))

    def sign(self, tx_out_script_db, secret_exponents, public_pair_compressed_for_hash160_lookup=None):
        """Sign a standard transaction.
        tx_out_script_db:
            a dictionary-like lookup of (hash, idx) => output script
            We need this to find the old tx output script so we can
            create a signature closing it out. Do something like this:
                tx_out_script_db = { (tx.hash(), idx) : tx_out.script
                        for tx in TX_LIST for idx, tx_out in enumerate(tx.txs_out)}
        secret_exponents:
            either an array of the relevant secret exponents OR
            a dictionary-like object that returns a secret_exponent for a public_pair.
            Do something like this:
               sefppl = dict(((public_pair_for_secret_exponent(generator_secp256k1, secret_exponent)) :
                   secret_exponent) for secret_exponent in secret_exponent_list)
        public_pair_compressed_for_hash160_lookup:
            an optional dictionary-like object that returns a tuple (public_pair, compressed) for the
            key public_pair_to_hash160_sec(public_pair, compressed=compressed)
            If this parameter is not included, it is generated by the list of secret exponents. However,
            if this list is long, it may take a long time.
        """

        # if secret_exponents is a list, we generate the lookup
        # build secret_exponent_for_public_pair_lookup

        if hasattr(secret_exponents, "get"):
            secret_exponent_for_public_pair_lookup = secret_exponents
        else:
            secret_exponent_for_public_pair_lookup = {}
            public_pair_compressed_for_hash160_lookup = {}
            for secret_exponent in secret_exponents:
                public_pair = public_pair_for_secret_exponent(generator_secp256k1, secret_exponent)
                secret_exponent_for_public_pair_lookup[public_pair] = secret_exponent
                public_pair_compressed_for_hash160_lookup[public_pair_to_hash160_sec(public_pair, compressed=True)] = (public_pair, True)
                public_pair_compressed_for_hash160_lookup[public_pair_to_hash160_sec(public_pair, compressed=False)] = (public_pair, False)

        new_txs_in = []
        for tx_in in self.txs_in:
            tx_out_script = tx_out_script_db.get((tx_in.previous_hash, tx_in.previous_index))
            # Leave out the signature from the hash, since a signature can't sign itself.
            # The checksig op will also drop the signatures from its hash.
            partial_hash = self.partial_hash(tx_out_script, tx_in.previous_index, signature_type=SIGHASH_ALL)

            new_script = solver(tx_out_script, partial_hash, secret_exponent_for_public_pair_lookup.get, public_pair_compressed_for_hash160_lookup.get, SIGHASH_ALL)

            new_txs_in.append(TxIn(tx_in.previous_hash, tx_in.previous_index, new_script))

            if not verify_script(new_script, tx_out_script, partial_hash, hash_type=0):
                raise ValidationFailureError("just signed script Tx %s TxIn index %d did not verify" % (b2h_rev(tx_in.previous_hash), tx_in.previous_index))

        tx = Tx(self.version, new_txs_in, self.txs_out, self.lock_timestamp)
        return tx

    def __str__(self):
        return "Tx [%s]" % self.id()

    def __repr__(self):
        return "Tx [%s] (v:%d) [%s] [%s]" % (self.id(), self.version, ", ".join(str(t) for t in self.txs_in), ", ".join(str(t) for t in self.txs_out))
