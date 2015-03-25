import json
try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

from pycoin.convention import btc_to_satoshi
from pycoin.serialize import b2h_rev, h2b, h2b_rev
from pycoin.tx.Tx import Tx, TxIn, TxOut
from pycoin.tx.script import tools


def get_json_for_hash(the_hash):
    d = urlopen("http://blockexplorer.com/rawtx/%s" % b2h_rev(the_hash)).read()
    return json.loads(d.decode("utf8"))


def get_tx(tx_hash):
    """
    Get a Tx by its hash.
    """
    # TODO: fix this
    j = get_json_for_hash(tx_hash)
    txs_in = []
    for j_in in j.get("in"):
        if j_in.get("coinbase"):
            txs_in.append(TxIn.coinbase_tx_in(h2b(j_in["coinbase"])))
        else:
            txs_in.append(TxIn(
                h2b_rev(j_in["prev_out"]["hash"]),
                int(j_in["prev_out"]["n"]),
                tools.compile(j_in["scriptSig"])))

    txs_out = []
    for j_out in j.get("out"):
        txs_out.append(TxOut(int(btc_to_satoshi(j_out["value"])), tools.compile(j_out["scriptPubKey"])))

    tx = Tx(int(j["ver"]), txs_in, txs_out, int(j["lock_time"]))
    assert tx.hash() == tx_hash
    return tx
