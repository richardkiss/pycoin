import json

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

from pycoin.serialize import h2b
from pycoin.tx import Spendable


class ChainProvider(object):
    def __init__(self, key_id):
        self.key_id = key_id

    def unspents_for_addresses(self, address_iter):
        """
        Return a list of Spendable objects for the
        given bitcoin address.
        """
        address_list = ",".join(address_iter)
        URL = "https://api.chain.com/v2/bitcoin/addresses/%s/unspents?api-key-id=%s" % (
            address_list, self.key_id)
        r = json.loads(urlopen(URL).read().decode("utf8"))

        spendables = []
        for u in r:
            coin_value = u["value"]
            script = h2b(u["script_hex"])
            previous_hash = h2b(u["transaction_hash"])
            previous_index = u["output_index"]
            spendables.append(Spendable(coin_value, script, previous_hash, previous_index))
        return spendables
