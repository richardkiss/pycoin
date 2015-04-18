import json

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

from pycoin.serialize import h2b
from pycoin.tx import Spendable


class ChainProvider(object):
    def __init__(self, key_id, netcode="BTC"):
        NETWORK_PATHS = {
            "BTC" : "bitcoin",
            "XTN" : "testnet3"
        }
        self.key_id = key_id
        self.network_path = NETWORK_PATHS.get(netcode)

    def base_url(self):
        return "https://api.chain.com/v2/%s/%%s?api-key-id=%s" % (self.network_path, self.key_id)

    def unspents_for_addresses(self, address_iter):
        """
        Return a list of Spendable objects for the
        given bitcoin address.
        """
        address_list = ",".join(address_iter)
        URL = self.base_url() % ("addresses/%s/unspents" % address_list)
        r = json.loads(urlopen(URL).read().decode("utf8"))

        spendables = []
        for u in r:
            coin_value = u["value"]
            script = h2b(u["script_hex"])
            previous_hash = h2b(u["transaction_hash"])
            previous_index = u["output_index"]
            spendables.append(Spendable(coin_value, script, previous_hash, previous_index))
        return spendables
