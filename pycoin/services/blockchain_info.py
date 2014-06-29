import io
import json

try:
    from urllib2 import urlopen, HTTPError
    from urllib import urlencode
except ImportError:
    from urllib.request import urlopen, HTTPError
    from urllib.parse import urlencode

from pycoin.serialize import b2h, h2b
from pycoin.tx import Spendable


def payments_for_address(bitcoin_address):
    "return an array of (TX ids, net_payment)"
    URL = "https://blockchain.info/address/%s?format=json" % bitcoin_address
    d = urlopen(URL).read()
    json_response = json.loads(d.decode("utf8"))
    response = []
    for tx in json_response.get("txs", []):
        total_out = 0
        for tx_out in tx.get("out", []):
            if tx_out.get("addr") == bitcoin_address:
                total_out += tx_out.get("value", 0)
        if total_out > 0:
            response.append((tx.get("hash"), total_out))
    return response


def spendables_for_address(bitcoin_address):
    """
    Return a list of Spendable objects for the
    given bitcoin address.
    """
    URL = "http://blockchain.info/unspent?active=%s" % bitcoin_address
    r = json.loads(urlopen(URL).read().decode("utf8"))
    spendables = []
    for u in r["unspent_outputs"]:
        coin_value = u["value"]
        script = h2b(u["script"])
        previous_hash = h2b(u["tx_hash"])
        previous_index = u["tx_output_n"]
        spendables.append(Spendable(coin_value, script, previous_hash, previous_index))
    return spendables


def send_tx(tx):
    s = io.BytesIO()
    tx.stream(s)
    tx_as_hex = b2h(s.getvalue())
    data = urlencode(dict(tx=tx_as_hex)).encode("utf8")
    URL = "http://blockchain.info/pushtx"
    try:
        d = urlopen(URL, data=data).read()
        return d
    except HTTPError as ex:
        d = ex.read()
        print(ex)
