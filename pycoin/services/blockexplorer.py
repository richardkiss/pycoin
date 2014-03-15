import binascii
import json
import urllib.request

from pycoin.tx.Tx import Tx, TxIn, TxInGeneration, TxOut
from pycoin.tx.script import tools

def h2b_rev(h):
    b = binascii.unhexlify(h)
    return bytearray(reversed(b))

def get_json_for_hash(the_hash):
    try:
        d = urllib.request.urlopen("http://blockexplorer.com/rawtx/%s" % the_hash).read()
        return json.loads(d.decode("utf8"))
    except urllib.error.HTTPError:
        pass

def fetch_tx(tx_hash, is_testnet=False):
    assert is_testnet == False
    j = get_json_for_hash(tx_hash)
    txs_in = []
    for j_in in j.get("in"):
        if j_in.get("coinbase"):
            txs_in.append(TxInGeneration(binascii.unhexlify(j_in["coinbase"])))
        else:
            txs_in.append(TxIn(h2b_rev(j_in["prev_out"]["hash"]), int(j_in["prev_out"]["n"]), tools.compile(j_in["scriptSig"])))

    txs_out = []
    for j_out in j.get("out"):
        txs_out.append(TxOut(int(float(j_out["value"]) * 1e8 + 0.5), tools.compile(j_out["scriptPubKey"])))

    tx = Tx(int(j["ver"]), txs_in, txs_out, int(j["lock_time"]))
    assert tx.id() == tx_hash
    return tx
