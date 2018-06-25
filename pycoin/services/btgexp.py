
from .agent import urlopen

from pycoin.coins.bgold.Tx import Tx
from pycoin.encoding.hexbytes import b2h_rev


class BTGExpProvider(object):
    def __init__(self):
        self.base_url = "http://btgexp.com/api/"

    def tx_for_tx_hash(self, tx_hash):
        URL = "%s/getrawtransaction?txid=%s&decrypt=0" % (self.base_url, b2h_rev(tx_hash))
        r = urlopen(URL).read().decode("utf8")
        tx = Tx.from_hex(r)
        if tx.hash() == tx_hash:
            return tx
        return None
