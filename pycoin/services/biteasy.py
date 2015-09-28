import json

try:
    from urllib2 import urlopen, Request
except ImportError:
    from urllib.request import urlopen, Request

from pycoin.serialize import b2h_rev, h2b, h2b_rev
from pycoin.tx import Spendable, Tx, TxIn, TxOut
from pycoin.tx.script import tools


def fetch_json(url_extension):
    URL = "https://api.biteasy.com/blockchain/v1/%s" % url_extension
    r = Request(URL,
                headers={
                    "content-type": "application/json",
                    "accept": "*/*",
                    "User-Agent": "curl/7.29.0"})
    d = urlopen(r).read()
    json_response = json.loads(d.decode("utf8"))

    return json_response


def balance_for_address(bitcoin_address, confidence=1):
    """
    Rerturns a basic balance for this address.
    """
    # From my basic testing I think biteasy only ever shows confirmed
    # transactions.
    if confidence != 1:
        raise Exception("biteasy only shows confirmed transactions")

    try:
        json_response = fetch_json("addresses/%s" % bitcoin_address)
    except Exception as e:
        if e.code == 404:
            # TODO: Can we distinguish between malformed requets and
            # unused addresses?
            # Assume this is an unused address:
            return [0, 0, 0]
        else:
            raise

    payload = json_response.get("data", {})
    return [
        payload.get("total_received"),
        payload.get("total_sent"),
        payload.get("balance")
    ]


def spendables_for_address(bitcoin_address):
    """
    Return a list of Spendable objects for the
    given bitcoin address.
    """
    json_response = fetch_json(
        "addresses/%s/unspent-outputs" % bitcoin_address)
    spendables = []
    for tx_out_info in json_response.get("data", {}).get("outputs"):
        if tx_out_info.get("to_address") == bitcoin_address:
            coin_value = tx_out_info["value"]
            script = tools.compile(tx_out_info.get("script_pub_key"))
            previous_hash = h2b_rev(tx_out_info.get("transaction_hash"))
            previous_index = tx_out_info.get("transaction_index")
            spendables.append(
                Spendable(coin_value, script, previous_hash, previous_index))
    return spendables


def tx_for_tx_hash(tx_hash):
    json_response = fetch_json("transactions/%s" % b2h_rev(tx_hash))
    tx = json_to_tx(json_response)
    if tx.hash() == tx_hash:
        return tx
    return None


def json_to_tx(json_response):
    # transactions with non-standard lock time are not decoded properly
    # for example, d1ef46055a84fd02ee82580d691064780def18614d98646371c3448ca20019ac
    # there is no way to fix this until biteasy add a lock_time field to their
    # output
    d = json_response.get("data")
    txs_in = []
    for d1 in d.get("inputs"):
        previous_hash = h2b_rev(d1.get("outpoint_hash"))
        previous_index = d1.get("outpoint_index")
        script = h2b(d1.get("script_sig"))
        sequence = 4294967295  # BRAIN DAMAGE
        txs_in.append(TxIn(previous_hash, previous_index, script, sequence))
    txs_out = []
    for d1 in d.get("outputs"):
        coin_value = d1.get("value")
        script = h2b(d1.get("script_pub_key"))
        txs_out.append(TxOut(coin_value, script))
    version = d.get("version")
    lock_time = 0  # BRAIN DAMAGE
    return Tx(version, txs_in, txs_out, lock_time)
