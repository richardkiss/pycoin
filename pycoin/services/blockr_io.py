import io
import json

from .agent import urlopen

from pycoin.convention import btc_to_satoshi
from pycoin.tx import Tx, Spendable
from pycoin.serialize import b2h_rev, h2b, h2b_rev


class BlockrioProvider(object):
    def __init__(self, netcode='BTC'):
        url_stub = {"BTC": "btc.blockr.io", "XTN": "tbtc.blockr.io"}.get(netcode)
        if url_stub is None:
            raise ValueError("unsupported netcode %s" % netcode)
        self.url = "https://%s/api/v1" % url_stub

    def spendables_for_address(self, address):
        """
        Return a list of Spendable objects for the
        given bitcoin address.
        """
        url_append = "unspent/%s" % address
        URL = "%s/address/%s" % (self.url, url_append)
        r = json.loads(urlopen(URL).read().decode("utf8"))
        spendables = []
        for u in r.get("data", {}).get("unspent", []):
            coin_value = btc_to_satoshi(u.get("amount"))
            script = h2b(u.get("script"))
            previous_hash = h2b_rev(u.get("tx"))
            previous_index = u.get("n")
            spendables.append(Spendable(coin_value, script, previous_hash, previous_index))
        return spendables

    def tx_for_tx_hash(self, tx_hash):
        "Get a Tx by its hash."
        URL = "%s/tx/raw/%s" % (self.url, b2h_rev(tx_hash))
        r = json.loads(urlopen(URL).read().decode("utf8"))
        tx = Tx.parse(io.BytesIO(h2b(r.get("data").get("tx").get("hex"))))
        return tx

    get_tx = tx_for_tx_hash


# Will keep these for backward compatibility
def spendables_for_address(bitcoin_address):
    return BlockrioProvider().spendables_for_address(bitcoin_address)


def get_tx(tx_hash):
    return BlockrioProvider().get_tx(tx_hash)
