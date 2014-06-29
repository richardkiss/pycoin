import io
import json

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

from pycoin.convention import btc_to_satoshi
from pycoin.tx import Tx, Spendable
from pycoin.serialize import b2h_rev, h2b, h2b_rev


def spendables_for_address(bitcoin_address):
    """
    Return a list of Spendable objects for the
    given bitcoin address.
    """
    URL = "http://btc.blockr.io/api/v1/address/unspent/%s" % bitcoin_address
    r = json.loads(urlopen(URL).read().decode("utf8"))
    spendables = []
    for u in r.get("data", {}).get("unspent", []):
        coin_value = btc_to_satoshi(u.get("amount"))
        script = h2b(u.get("script"))
        previous_hash = h2b_rev(u.get("tx"))
        previous_index = u.get("n")
        spendables.append(Spendable(coin_value, script, previous_hash, previous_index))
    return spendables


def get_tx(tx_hash):
    """
    Get a Tx by its hash.
    """
    URL = "http://btc.blockr.io/api/v1/tx/raw/%s" % b2h_rev(tx_hash)
    r = json.loads(urlopen(URL).read().decode("utf8"))
    tx = Tx.parse(io.BytesIO(h2b(r.get("data").get("tx").get("hex"))))
    return tx
