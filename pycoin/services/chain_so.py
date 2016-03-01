import io
import json

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

from pycoin.serialize import b2h_rev, h2b, h2b_rev
from pycoin.tx import Spendable, Tx


class ChainSoProvider(object):
    def __init__(self, netcode="BTC"):
        NETWORK_PATHS = {
            "BTC": "BTC",
            "XTN": "BTCTEST",
            "DOGE": "DOGE",
            "XDT": "DOGETEST",
        }
        self.network_path = NETWORK_PATHS.get(netcode)

    def base_url(self, method, args):
        return "https://chain.so/api/v2/%s/%s/%s" % (method, self.network_path, args)

    def spendables_for_address(self, address):
        """
        Return a list of Spendable objects for the
        given bitcoin address.
        """
        spendables = []
        r = json.loads(urlopen(self.base_url('get_tx_unspent', address)).read().decode("utf8"))

        for u in r['data']['txs']:
            coin_value = int(float(u['value']) * 100000000)
            script = h2b(u["script_hex"])
            previous_hash = h2b_rev(u["txid"])
            previous_index = u["output_no"]
            spendables.append(Spendable(coin_value, script, previous_hash, previous_index))

        return spendables

    def tx_for_tx_hash(self, tx_hash):
        "Get a Tx by its hash."
        url = self.base_url("get_tx", b2h_rev(tx_hash))
        r = json.loads(urlopen(url).read().decode("utf8"))
        tx = Tx.parse(io.BytesIO(h2b(r.get("data").get("tx_hex"))))
        return tx
