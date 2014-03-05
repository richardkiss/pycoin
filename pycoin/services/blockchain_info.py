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

# These are the fields we care about for Tx signing
UNSPENT_OUTPUT_FIELDS = ['value', 'script', 'tx_hash', 'tx_output_n',]
def unspent_outputs_for_address(bitcoin_address):
    """
    Fetch data from BCI.
    Can be used to take to airgap machine for offline signing.
    """
    URL = "http://blockchain.info/unspent?active=%s" % bitcoin_address
    r = json.loads(urlopen(URL).read().decode("utf8"))

    # Get rid of unneccesary fields
    unspent_outputs_cleaned = []
    for unspent_output in r["unspent_outputs"]:
        unspent_output_cleaned = {}
        for unspent_output_field in UNSPENT_OUTPUT_FIELDS:
            unspent_output_cleaned[unspent_output_field] = unspent_output[unspent_output_field]
        unspent_outputs_cleaned.append(unspent_output_cleaned)
    return unspent_outputs_cleaned

def coin_sources_for_unspent_outputs(unspent_outputs):
    """"
    Take unspent outputs and return an array of elements of the following form for signing:
        (tx_hash, tx_output_index, tx_out)
        tx_out is a TxOut item with attrs "value" & "script"
    """
    coins_sources = []
    for unspent_output in unspent_outputs:
        tx_out = TxOut(unspent_output["value"], binascii.unhexlify(unspent_output["script"].encode()))
        coins_source = (binascii.unhexlify(unspent_output["tx_hash"].encode()), unspent_output["tx_output_n"], tx_out)
        coins_sources.append(coins_source)
    return coins_sources

def coin_sources_for_address(bitcoin_address):
    """"
    return an array of elements of the form:
        (tx_hash, tx_output_index, tx_out)
        tx_out is a TxOut item with attrs "value" & "script"

    Use this method for online transaction signing.
    Use the two methods below for offline signing.
    """
    unspent_outputs = unspent_outputs_for_address(bitcoin_address)
    return coin_sources_for_unspent_outputs(unspent_outputs)

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
