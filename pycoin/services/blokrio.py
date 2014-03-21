import binascii
import io
import json

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

from pycoin.convention import btc_to_satoshi
from pycoin.tx import Tx, TxOut
from pycoin.serialize import b2h_rev, h2b_rev


def unspent_for_address(bitcoin_address):
    """
    Return a list of tuples of the form:
      (previous_hash, previous_index, tx_out)
    """
    URL = "http://btc.blockr.io/api/v1/address/unspent/%s" % bitcoin_address
    r = json.loads(urlopen(URL).read().decode("utf8"))
    unspent_tx_tuples = []
    for u in r.get("data", {}).get("unspent", []):
        coin_value = btc_to_satoshi(u.get("amount"))
        script = binascii.unhexlify(u.get("script"))
        previous_hash = h2b_rev(u.get("tx"))
        previous_index = u.get("n")
        tx_out = TxOut(coin_value, script)
        unspent_tx_tuple = (previous_hash, previous_index, tx_out)
        unspent_tx_tuples.append(unspent_tx_tuple)
    return unspent_tx_tuples


def get_tx(tx_hash):
    URL = "http://btc.blockr.io/api/v1/tx/raw/%s" % b2h_rev(tx_hash)
    r = json.loads(urlopen(URL).read().decode("utf8"))
    tx = Tx.parse(io.BytesIO(binascii.unhexlify(r.get("data").get("tx").get("hex"))))
    return tx
