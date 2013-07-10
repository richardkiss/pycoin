#!/usr/bin/env python

import binascii
import io
import json
import sys
import urllib.request

from pycoin.tx.Tx import Tx, TxIn, TxOut
from pycoin.tx.script import tools

def h2b_rev(h):
    b = binascii.unhexlify(h)
    return bytes(reversed(b))

def get_json_for_hash(the_hash):
    d = urllib.request.urlopen("http://blockexplorer.com/rawtx/%s" % the_hash).read()
    return json.loads(d.decode("utf8"))

def linebreak(s, max_width):
    s1 = [s[i:i+max_width] for i in range(0, len(s), max_width)]
    return '\n'.join(s1)

def main():
    the_hash = sys.argv[1]
    j = get_json_for_hash(the_hash)
    txs_in = []
    for j_in in j.get("in"):
        txs_in.append(TxIn(h2b_rev(j_in["prev_out"]["hash"]), int(j_in["prev_out"]["n"]), tools.compile(j_in["scriptSig"])))

    txs_out = []
    for j_out in j.get("out"):
        txs_out.append(TxOut(int(float(j_out["value"]) * 1e8 + 0.5), tools.compile(j_out["scriptPubKey"])))

    tx = Tx(int(j["ver"]), txs_in, txs_out, int(j["lock_time"]))
    assert tx.id() == the_hash
    s = io.BytesIO()
    tx.stream(s)
    v = s.getvalue()
    print(linebreak(binascii.b2a_base64(v).decode("utf8"), 72))

main()
