""" - create_and_sign(spendables, payables, wifs/secret_exponent_db, fee="standard", locktime=0)
    - spendables:
      - list of spendable
      - see above
    - payables:
      - list of payables
        - a 2-tuple of (bitcoin_address, amount)
        - a bitcoin address
        - reserve fees + given amounts
        - if some amounts are missing, split unclaimed amounts equally
    - wifs:
      - an iterable that creates the DB
    - secret_exponent_db:
      - a dictionary or an interable
        - if it supports __contains__, it's a dict
      - if it's iterable, expand (lazily) to a dictionary
  - return a Tx
  - failures:
    - ValueError for bad payable
    - SecretExponentMissing for a given bitcoin address
    - InsufficentFunds because of fees, payouts, or dust
"""

from ..encoding import wif_to_secret_exponent
from ..convention import tx_fee
from .TxOut import TxOut, standard_tx_out_script
from .Tx import Tx
from .script.solvers import build_hash160_lookup_db


class SecretExponentMissing(Exception):
    pass


class LazySecretExponentDB(object):
    def __init__(self, wif_iterable, secret_exponent_db_cache):
        self.wif_iterable = iter(wif_iterable)
        self.secret_exponent_db_cache = secret_exponent_db_cache

    def get(self, v):
        if v in self.secret_exponent_db_cache:
            return self.secret_exponent_db_cache[v]
        for wif in self.wif_iterable:
            secret_exponent = wif_to_secret_exponent(wif)
            d = build_hash160_lookup_db([secret_exponent])
            self.secret_exponent_db_cache.update(d)
            if v in self.secret_exponent_db_cache:
                return self.secret_exponent_db_cache[v]
        self.wif_iterable = []
        return None


def create_and_sign_tx(spendables, payables, wifs=[], fee="standard",
                       lock_time=0, secret_exponent_db={}, is_test=False):
    txs_in = [spendable.tx_in() for spendable in spendables]

    txs_out = []

    for payable in payables:
        if len(payable) == 2:
            bitcoin_address, coin_value = payable
        else:
            bitcoin_address = payable
            coin_value = 0
        script = standard_tx_out_script(bitcoin_address, is_test=is_test)
        txs_out.append(TxOut(coin_value, script))

    tx = Tx(version=1, txs_in=txs_in, txs_out=txs_out, lock_time=lock_time)
    tx.set_unspents(spendables)

    # calculate fees
    if fee == 'standard':
        ## TODO: improve this
        # 1: the tx is not fully built out, so it will actually be larger than implied at this point
        # 2: recommended_fee_for_tx gives estimates that are too high
        fee = tx_fee.recommended_fee_for_tx(tx)

    # calculate coin values
    zero_count = sum(1 for tx_out in tx.txs_out if tx_out.coin_value == 0)
    if zero_count > 0:
        total_coin_value = sum(spendable.coin_value for spendable in spendables)
        coins_allocated = sum(tx_out.coin_value for tx_out in txs_out) + fee
        remaining_coins = total_coin_value - coins_allocated
        if remaining_coins < 0:
            raise ValueError("insufficient inputs for outputs")
        value_each, extra_count = divmod(remaining_coins, zero_count)
        if value_each < 1:
            raise ValueError("not enough to pay nonzero amounts to at least one of the unspecified outputs")
        for tx_out in tx.txs_out:
            if tx_out.coin_value == 0:
                tx_out.coin_value = value_each + (1 if extra_count > 0 else 0)
                extra_count -= 1

    tx = tx.sign(LazySecretExponentDB(wifs, secret_exponent_db))

    for idx, tx_out in enumerate(tx.txs_in):
        if not tx.is_signature_ok(idx):
            raise SecretExponentMissing("failed to sign spendable for %s" %
                                        spendable[idx].bitcoin_address(is_test=False))

    return tx
