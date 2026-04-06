from __future__ import annotations

from typing import Any

from pycoin.encoding.hexbytes import b2h, b2h_rev
from pycoin.coins.bitcoin.Tx import Tx


class BitcoindProvider:
    def __init__(self, bitcoind_url: str) -> None:
        try:
            from bitcoinrpc.authproxy import AuthServiceProxy
        except ImportError:
            print("This script depends upon python-bitcoinrpc.")
            print(
                "pip install -e git+https://github.com/jgarzik/"
                "python-bitcoinrpc#egg=python_bitcoinrpc-master"
            )
            raise
        self.bitcoind_url = bitcoind_url
        self.connection = AuthServiceProxy(bitcoind_url)

    def bitcoind_agrees_on_transaction_validity(self, tx: Any) -> bool:
        tx.check_unspents()
        unknown_tx_outs = [
            unspent_to_bitcoind_dict(tx_in, tx_out)
            for tx_in, tx_out in zip(tx.txs_in, tx.unspents)
        ]
        signed = self.connection.signrawtransaction(tx.as_hex(), unknown_tx_outs, [])
        is_ok = [tx.is_solution_ok(idx) for idx in range(len(tx.txs_in))]
        return all(is_ok) == signed.get("complete")  # type: ignore[no-any-return]

    def tx_for_tx_hash(self, tx_hash: bytes) -> Any:
        raw_tx = self.connection.getrawtransaction(b2h_rev(tx_hash))
        tx = Tx.from_hex(raw_tx)
        return tx


def unspent_to_bitcoind_dict(tx_in: Any, tx_out: Any) -> dict[str, Any]:
    return dict(
        txid=b2h_rev(tx_in.previous_hash),
        vout=tx_in.previous_index,
        scriptPubKey=b2h(tx_out.script),
    )


def bitcoind_agrees_on_transaction_validity(bitcoind_url: str, tx: Any) -> bool:
    bp = BitcoindProvider(bitcoind_url)
    return bp.bitcoind_agrees_on_transaction_validity(tx)
