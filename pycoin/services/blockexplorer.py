import json
try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

from pycoin.serialize import b2h_rev
from pycoin.tx.Tx import Tx


class BlockExplorerProvider(object):
    def __init__(self, netcode):
        url_stub = {"BTC": "blockexplorer.com", "XTN": "testnet.blockexplorer.com"}.get(netcode)
        if url_stub is None:
            raise ValueError("unsupported netcode %s" % netcode)
        self.url = "http://%s/api" % url_stub

    def tx_for_tx_hash(self, tx_hash):
        """
        Get a Tx by its hash.
        """
        url = "%s/rawtx/%s" % (self.url, b2h_rev(tx_hash))
        d = urlopen(url).read()
        j = json.loads(d.decode("utf8"))
        tx = Tx.from_hex(j.get("rawtx", ""))
        if tx.hash() == tx_hash:
            return tx
