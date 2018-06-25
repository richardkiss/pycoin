# provide support to insight API servers
# see also https://github.com/bitpay/insight-api

import decimal
import json
import io

from .agent import request, urlencode, urlopen

from pycoin.block import Block
from pycoin.coins.bitcoin.ScriptTools import BitcoinScriptTools
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.convention import btc_to_satoshi
from pycoin.encoding.hash import double_sha256
from pycoin.encoding.hexbytes import b2h, b2h_rev, h2b, h2b_rev
from pycoin.merkle import merkle
from pycoin.networks.default import get_current_netcode


class InsightProvider(object):
    def __init__(self, base_url="https://insight.bitpay.com", netcode=None):
        if netcode is None:
            netcode = get_current_netcode()
        while base_url[-1] == '/':
            base_url = base_url[:-1]
        self.base_url = base_url

    def get_blockchain_tip(self):
        URL = "%s/status?q=getLastBlockHash" % self.base_url
        d = urlopen(URL).read().decode("utf8")
        r = json.loads(d)
        return h2b_rev(r.get("lastblockhash"))

    def get_blockheader(self, block_hash):
        return self.get_blockheader_with_transaction_hashes(block_hash)[0]

    def get_blockheader_with_transaction_hashes(self, block_hash):
        URL = "%s/block/%s" % (self.base_url, b2h_rev(block_hash))
        r = json.loads(urlopen(URL).read().decode("utf8"))
        version = r.get("version")
        previous_block_hash = h2b_rev(r.get("previousblockhash"))
        merkle_root = h2b_rev(r.get("merkleroot"))
        timestamp = r.get("time")
        difficulty = int(r.get("bits"), 16)
        nonce = int(r.get("nonce"))
        tx_hashes = [h2b_rev(tx_hash) for tx_hash in r.get("tx")]
        blockheader = Block(version, previous_block_hash, merkle_root, timestamp, difficulty, nonce)
        if blockheader.hash() != block_hash:
            return None, None
        calculated_hash = merkle(tx_hashes, double_sha256)
        if calculated_hash != merkle_root:
            return None, None
        blockheader.height = r.get("height")
        return blockheader, tx_hashes

    def get_block_height(self, block_hash):
        return self.get_blockheader_with_transaction_hashes(block_hash)[0].height

    def tx_for_tx_hash(self, tx_hash):
        URL = "%s/tx/%s" % (self.base_url, b2h_rev(tx_hash))
        r = json.loads(urlopen(URL).read().decode("utf8"))
        tx = tx_from_json_dict(r)
        if tx.hash() == tx_hash:
            return tx
        return None

    def get_tx_confirmation_block(self, tx_hash):
        return self.get_tx(tx_hash).confirmation_block_hash

    def spendables_for_address(self, address):
        """
        Return a list of Spendable objects for the
        given bitcoin address.
        """
        URL = "%s/addr/%s/utxo" % (self.base_url, address)
        r = json.loads(urlopen(URL).read().decode("utf8"))
        spendables = []
        for u in r:
            coin_value = btc_to_satoshi(str(u.get("amount")))
            script = h2b(u.get("scriptPubKey"))
            previous_hash = h2b_rev(u.get("txid"))
            previous_index = u.get("vout")
            spendables.append(Tx.Spendable(coin_value, script, previous_hash, previous_index))
        return spendables

    def spendables_for_addresses(self, addresses):
        spendables = []
        for addr in addresses:
            spendables.extend(self.spendables_for_address(addr))
        return spendables

    def send_tx(self, tx):
        s = io.BytesIO()
        tx.stream(s)
        tx_as_hex = b2h(s.getvalue())
        data = urlencode(dict(rawtx=tx_as_hex)).encode("utf8")
        URL = "%s/tx/send" % self.base_url
        try:
            d = urlopen(URL, data=data).read()
            return d
        except request.HTTPError as err:
            if err.code == 400:
                raise ValueError(err.readline())
            raise err


def tx_from_json_dict(r):
    version = r.get("version")
    lock_time = r.get("locktime")
    txs_in = []
    for vin in r.get("vin"):
        if "coinbase" in vin:
            previous_hash = b'\0' * 32
            script = h2b(vin.get("coinbase"))
            previous_index = 4294967295
        else:
            previous_hash = h2b_rev(vin.get("txid"))
            scriptSig = vin.get("scriptSig")
            if "hex" in scriptSig:
                script = h2b(scriptSig.get("hex"))
            else:
                script = BitcoinScriptTools.compile(scriptSig.get("asm"))
            previous_index = vin.get("vout")
        sequence = vin.get("sequence")
        txs_in.append(Tx.TxIn(previous_hash, previous_index, script, sequence))
    txs_out = []
    for vout in r.get("vout"):
        coin_value = btc_to_satoshi(decimal.Decimal(vout.get("value")))
        script = BitcoinScriptTools.compile(vout.get("scriptPubKey").get("asm"))
        txs_out.append(Tx.TxOut(coin_value, script))
    tx = Tx(version, txs_in, txs_out, lock_time)
    bh = r.get("blockhash")
    if bh:
        bh = h2b_rev(bh)
    tx.confirmation_block_hash = bh
    return tx
