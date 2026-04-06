from __future__ import annotations

import io
import json
import warnings
from typing import Any

from .agent import request, urlencode, urlopen

from pycoin.coins.bitcoin.Tx import Tx
from pycoin.encoding.hexbytes import b2h, h2b, b2h_rev


class BlockchainInfoProvider:
    def __init__(self, netcode: str) -> None:
        if netcode == "BTC":
            self.api_domain = "https://blockchain.info"
        elif netcode == "XTN":
            self.api_domain = "https://testnet.blockchain.info"
        elif netcode == "BCH":
            self.api_domain = "http://api.blockchain.info/bch"
        else:
            raise ValueError("unsupported netcode %s" % netcode)

    def tx_for_tx_hash(self, tx_hash: bytes) -> Any:
        "Get a Tx by its hash."
        URL = self.api_domain + ("/rawtx/%s?format=hex" % b2h_rev(tx_hash))
        tx = Tx.from_hex(urlopen(URL).read().decode("utf8"))
        return tx

    def payments_for_address(self, address: str) -> list[tuple[str, int]]:
        "return an array of (TX ids, net_payment)"
        URL = self.api_domain + ("/address/%s?format=json" % address)
        d = urlopen(URL).read()
        json_response = json.loads(d.decode("utf8"))
        response = []
        for tx in json_response.get("txs", []):
            total_out = 0
            for tx_out in tx.get("out", []):
                if tx_out.get("addr") == address:
                    total_out += tx_out.get("value", 0)
            if total_out > 0:
                response.append((tx.get("hash"), total_out))
        return response

    def spendables_for_address(self, address: str) -> list[Any]:
        """
        Return a list of Spendable objects for the
        given bitcoin address.
        """
        URL = self.api_domain + "/unspent?active=%s" % address
        r = json.loads(urlopen(URL).read().decode("utf8"))
        spendables = []
        for u in r["unspent_outputs"]:
            coin_value = u["value"]
            script = h2b(u["script"])
            previous_hash = h2b(u["tx_hash"])
            previous_index = u["tx_output_n"]
            spendables.append(
                Tx.Spendable(coin_value, script, previous_hash, previous_index)
            )
        return spendables

    def broadcast_tx(self, tx: Any) -> bytes:
        s = io.BytesIO()
        tx.stream(s)
        tx_as_hex = b2h(s.getvalue())
        data = urlencode(dict(tx=tx_as_hex)).encode("utf8")
        URL = self.api_domain + "/pushtx"
        try:
            d: bytes = urlopen(URL, data=data).read()
            return d
        except request.HTTPError as ex:
            try:
                ex.msg = ex.read().decode("utf8")  # type: ignore[attr-defined]
            except Exception:
                pass
            raise ex


def send_tx(self: Any, tx: Any) -> bytes:
    warnings.warn(
        "use BlockchainInfoProvider.broadcast_tx instead of send_tx",
        category=DeprecationWarning,
    )
    return BlockchainInfoProvider("BTC").broadcast_tx(tx)
