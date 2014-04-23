import json

try:
    from urllib2 import urlopen, Request
except ImportError:
    from urllib.request import urlopen, Request

from pycoin.serialize import h2b_rev
from pycoin.tx import Spendable
from pycoin.tx.script import tools


def spendables_for_address(bitcoin_address):
    """
    Return a list of Spendable objects for the
    given bitcoin address.
    """
    URL = "https://api.biteasy.com/blockchain/v1/addresses/%s/unspent-outputs" % bitcoin_address
    r = Request(URL,
                headers={"content-type": "application/json", "accept": "*/*", "User-Agent": "curl/7.29.0"})
    d = urlopen(r).read()
    json_response = json.loads(d.decode("utf8"))
    spendables = []
    for tx_out_info in json_response.get("data", {}).get("outputs"):
        if tx_out_info.get("to_address") == bitcoin_address:
            coin_value = tx_out_info["value"]
            script = tools.compile(tx_out_info.get("script_pub_key"))
            previous_hash = h2b_rev(tx_out_info.get("transaction_hash"))
            previous_index = tx_out_info.get("transaction_index")
            spendables.append(Spendable(coin_value, script, previous_hash, previous_index))
    return spendables
