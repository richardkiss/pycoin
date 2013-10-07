import binascii
import io
import json
import logging

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

from ..tx import TxOut

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

def coin_sources_for_address(bitcoin_address):
    """"
    return an array of elements of the form:
        (tx_hash, tx_output_index, tx_out)
        tx_out is a TxOut item with attrs "value" & "script"
    """
    URL = "http://blockchain.info/unspent?active=%s" % bitcoin_address
    r = json.loads(urlopen(URL).read().decode("utf8"))
    coins_sources = []
    for unspent_output in r["unspent_outputs"]:
        tx_out = TxOut(unspent_output["value"], binascii.unhexlify(unspent_output["script"].encode()))
        coins_source = (binascii.unhexlify(unspent_output["tx_hash"].encode()), unspent_output["tx_output_n"], tx_out)
        coins_sources.append(coins_source)
    return coins_sources

def send_tx(tx):
    s = io.BytesIO()
    tx.stream(s)
    tx_as_hex = binascii.hexlify(s.getvalue()).decode("utf8")
    data = urllib.parse.urlencode(dict(tx=tx_as_hex)).encode("utf8")
    URL = "http://blockchain.info/pushtx"
    try:
        d = urlopen(URL, data=data).read()
        return d
    except urllib.error.HTTPError as ex:
        d = ex.read()
        import pdb; pdb.set_trace()
        print(ex)
