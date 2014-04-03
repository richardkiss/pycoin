import binascii
import io
import json
import logging

try:
    from urllib2 import urlopen, Request
except ImportError:
    from urllib.request import urlopen, Request

from pycoin.tx import TxOut
from pycoin.tx.script import tools

def unspent_tx_outs_for_address(bitcoin_address):
    "return an array of (TX ids, net_payment)"
    URL = "https://api.biteasy.com/blockchain/v1/addresses/%s/unspent-outputs" % bitcoin_address
    #URL = "http://127.0.0.1:9999/blockchain/v1/addresses/%s/unspent-outputs" % bitcoin_address
    r = Request(URL, headers={"content-type": "application/json", "accept": "*/*", "User-Agent": "curl/7.29.0" })
    d = urlopen(r).read()
    json_response = json.loads(d.decode("utf8"))
    response = []

    for tx_out_info in json_response.get("data", {}).get("outputs"):
        if tx_out_info.get("to_address") == bitcoin_address:
            t = (tx_out_info.get("transaction_hash"), tx_out_info.get("transaction_index"), tools.compile(tx_out_info.get("script_pub_key")), tx_out_info.get("value"))
            response.append(t)
    return response

v = unspent_tx_outs_for_address("1KissFDVu2wAYWPRm4UGh5ZCDU9sE9an8T")
print(v)
