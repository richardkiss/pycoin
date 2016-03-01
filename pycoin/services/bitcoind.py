from pycoin.serialize import b2h, b2h_rev


class BitcoindProvider(object):
    def __init__(self, bitcoind_url):
        try:
            from bitcoinrpc.authproxy import AuthServiceProxy
        except ImportError:
            print("This script depends upon python-bitcoinrpc.")
            print("pip install -e git+https://github.com/jgarzik/"
                  "python-bitcoinrpc#egg=python_bitcoinrpc-master")
            raise
        self.bitcoind_url = bitcoind_url
        self.connection = AuthServiceProxy(bitcoind_url)

    def bitcoind_agrees_on_transaction_validity(self, tx):
        tx.check_unspents()
        unknown_tx_outs = [unspent_to_bitcoind_dict(tx_in, tx_out)
                           for tx_in, tx_out in zip(tx.txs_in, tx.unspents)]
        signed = self.connection.signrawtransaction(tx.as_hex(), unknown_tx_outs, [])
        is_ok = [tx.is_signature_ok(idx) for idx in range(len(tx.txs_in))]
        return all(is_ok) == signed.get("complete")


def unspent_to_bitcoind_dict(tx_in, tx_out):
    return dict(
        txid=b2h_rev(tx_in.previous_hash),
        vout=tx_in.previous_index,
        scriptPubKey=b2h(tx_out.script)
    )


def bitcoind_agrees_on_transaction_validity(bitcoind_url, tx):
    bp = BitcoindProvider(bitcoind_url)
    return bp.bitcoind_agrees_on_transaction_validity(tx)
