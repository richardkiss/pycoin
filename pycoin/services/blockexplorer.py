import json
from .agent import urlopen

from pycoin.coins.bitcoin.Tx import Tx
from pycoin.encoding.hexbytes import b2h_rev


class BlockExplorerProvider(object):
    def __init__(self, netcode):
        url_stub = {"BTC": "blockexplorer.com", "XTN": "testnet.blockexplorer.com", "BCH": "bitcoincash.blockexplorer.com"}.get(netcode)
        if url_stub is None:
            raise ValueError("unsupported netcode %s" % netcode)
        self.url = "https://%s/api" % url_stub

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
