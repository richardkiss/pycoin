# -*- coding: utf-8 -*-
"""
Helper code for airgap signing.

The MIT License (MIT)

Copyright (c) 2014 by Richard Kiss

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

from .TxOut import TxOut


def stream_minimal_tx_db_for_tx(tx_db, f, tx):
    """
    A minimal tx_db is a dictionary with TxOut lookups
    for a specific Tx. It's streamable to make air-gap Tx
    signing simple.

    This function streams a minimal tx_db to the given file-like object f.
    The input can be a real Tx DB or a minimal one.
    """
    for idx, tx_in in enumerate(tx.txs_in):
        tx_out = tx_db.get(tx_in.previous_hash).txs_out[tx_in.previous_index]
        tx_out.stream(f)


def minimal_tx_db_for_txs_out(tx, txs_out):
    """
    Attempt to load the minimal tx_db for a given transaction.
    """
    class TxStandin(object):
        def hash(self, *args, **kwargs):
            return None

    db = {}
    # create empty transactions at each hash
    for h in set([tx_in.previous_hash for tx_in in tx.txs_in]):
        db[h] = TxStandin()
        db[h].txs_out = {}

    # now make sure the archived tx_out values work
    for idx, (tx_in, tx_out) in enumerate(zip(tx.txs_in, txs_out)):
        db[tx_in.previous_hash].txs_out[tx_in.previous_index] = tx_out

    return db


def parse_minimal_tx_db_for_tx(f, tx):
    """
    Attempt to load the minimal tx_db for a given transaction.
    """
    return minimal_tx_db_for_txs_out(tx, (TxOut.parse(f) for i in enumerate(tx.txs_in)))
