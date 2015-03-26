
import json
import io

try:
    from urllib2 import urlopen, HTTPError
    from urllib import urlencode
except ImportError:
    from urllib.request import urlopen, HTTPError
    from urllib.parse import urlencode

from pycoin.serialize import b2h, h2b, h2b_rev
from pycoin.tx import Spendable



def spendables_for_address(address, netcode='BTC', chain_key = "DEMO-4a5e1e4"):
    """
    Return list of Spendable objects for the address
    """

    #Support for bitcoin testnet api in chain.com
    if netcode == "XTN":
        URL = "https://api.chain.com/v2/testnet3/addresses/%s/unspents?api-key-id=%s" % (address, chain_key)
    if netcode == "BTC":
        URL = "https://api.chain.com/v2/bitcoin/addresses/%s/unspents?api-key-id=%s" % (address, chain_key)
    r = json.loads(urlopen(URL).read().decode("utf8"))
    spendables = []
    for unspent in r:
        coin_value = unspent.get("value")
        script = h2b(unspent.get("script_hex"))
        previous_hash = h2b_rev(unspent.get("transaction_hash"))
        previous_index = unspent.get("output_index")
        spendables.append(Spendable(coin_value, script, previous_hash, previous_index))
    return spendables

