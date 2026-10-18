from __future__ import annotations

import json
from typing import Any

from .agent import urlopen

from pycoin.coins.bitcoin.Tx import Tx
from pycoin.convention import btc_to_satoshi
from pycoin.encoding.hexbytes import b2h_rev, h2b, h2b_rev
from pycoin.networks.default import get_current_netcode


class ChainSoProvider:
    def __init__(self, netcode: str | None = None) -> None:
        # no "XTN": SoChain's BTCTEST is Bitcoin testnet4, and XTN is testnet3
        NETWORK_PATHS = {
            "BTC": "BTC",
            "DOGE": "DOGE",
            "XDT": "DOGETEST",
        }
        if netcode is None:
            netcode = get_current_netcode()
        self.network_path = NETWORK_PATHS.get(netcode)

    def base_url(self, method: str, args: str) -> str:
        return "https://sochain.com/api/v3/%s/%s/%s" % (method, self.network_path, args)

    def spendables_for_address(self, address: str) -> list[Any]:
        """
        Return a list of Spendable objects for the
        given bitcoin address.
        """
        spendables = []
        page = 1
        while True:
            url = self.base_url("unspent_outputs", f"{address}/{page}")
            r = json.loads(urlopen(url).read().decode("utf8"))
            outputs = r["data"]["outputs"]

            for u in outputs:
                coin_value = btc_to_satoshi(u["value"])
                script = h2b(u["script"])
                previous_hash = h2b_rev(u["hash"])
                previous_index = u["index"]
                spendables.append(
                    Tx.Spendable(coin_value, script, previous_hash, previous_index)
                )

            # ten outputs come per page, and a shorter page is the last one
            if len(outputs) < 10:
                break
            page += 1

        return spendables

    def tx_for_tx_hash(self, tx_hash: bytes) -> Any:
        "Get a Tx by its hash."
        url = self.base_url("transaction", b2h_rev(tx_hash))
        r = json.loads(urlopen(url).read().decode("utf8"))
        d = r["data"]
        # the v3 API returns a transaction's parts, not its hex, so rebuild it
        txs_in = []
        for vin in d["inputs"]:
            previous_output = vin["previous_output"]
            if previous_output is None:
                # coinbase
                previous_hash = b"\0" * 32
                previous_index = 4294967295
            else:
                previous_hash = h2b_rev(previous_output["hash"])
                previous_index = previous_output["index"]
            script = h2b(vin["scriptSig"]["hex"])
            tx_in = Tx.TxIn(previous_hash, previous_index, script, vin["sequence"])
            tx_in.witness = [h2b(w) for w in vin["witness"]]
            txs_in.append(tx_in)
        txs_out = []
        for vout in d["outputs"]:
            coin_value = btc_to_satoshi(vout["value"])
            txs_out.append(Tx.TxOut(coin_value, h2b(vout["script"]["hex"])))
        tx = Tx(d["version"], txs_in, txs_out, d["locktime"])
        if tx.hash() == tx_hash:
            return tx
        return None
