
from ..encoding import wif_to_secret_exponent
from ..convention import tx_fee
from ..serialize import b2h_rev, h2b_rev

from .Spendable import Spendable
from .Tx import Tx
from .TxOut import TxOut, standard_tx_out_script
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


def created_signed_tx(spendables, payables, wifs=[], fee="standard",
                      lock_time=0, secret_exponent_db={}, is_test=False):
    """
    This function provides the easiest way to create and sign a transaction.

    All coin values are in satoshis.

    spendables:
        a list of Spendable objects, which act as inputs. These can
        be either a Spendable or a Spendable.as_text or a Spendable.as_dict
        if you prefer a non-object-based input (which might be easier for
        airgapped transactions, for example).
    payables:
        a list where each entry is a bitcoin address, or a tuple of
        (bitcoin address, coin_value). If the coin_value is missing or
        zero, this address is thrown into the "split pool". Funds not
        explicitly claimed by the fee or a bitcoin address are shared as
        equally as possible among the split pool. [Minor point: if the
        amount to be split does not divide evenly, some of the earlier
        bitcoin addresses will get an extra satoshi.]
    wifs:
        the list of WIFs required to sign this transaction.
    fee:
        a value, or "standard" for it to be calculated.
    lock_time:
        the lock_time to use in the transaction. Normally 0.
    secret_exponent_db:
        an optional dictionary (or any object with a .get method) that contains
        a bitcoin address => (secret_exponent, public_pair, is_compressed)
        tuple. This will be built automatically lazily with the list of WIFs.
        You can pass in an empty dictionary and as WIFs are processed, they
        will be cached here. If you have multiple transactions to sign, each with
        the same WIF list, passing a cache dictionary in may speed things up a bit.
    is_test:
        True for testnet, False for mainnet.

    Returns the signed Tx transaction, or raises an exception.

    At least one of "wifs" and "secret_exponent_db" must be included for there
    to be any hope of signing the transaction.

    Example:

    tx = created_signed_tx(
        spendables_for_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ["1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"],
        wifs=["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"],
        fee=0)

    This will move all available reported funds from 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    to 1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP, with no transaction fees (which means it might
    take a while to confirm, possibly never).
    """

    def _fix_spendable(s):
        if isinstance(s, Spendable):
            return s
        if isinstance(s, str):
            return Spendable.from_text(s)
        return Spendable.from_dict(s)

    spendables = [_fix_spendable(s) for s in spendables]
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

    tx.sign(LazySecretExponentDB(wifs, secret_exponent_db))

    for idx, tx_out in enumerate(tx.txs_in):
        if not tx.is_signature_ok(idx):
            raise SecretExponentMissing("failed to sign spendable for %s" %
                                        tx.unspents[idx].bitcoin_address(is_test=False))

    return tx


class BadSpendableError(Exception):
    pass

def validate_unspents(tx, tx_db):
    """
    Spendable objects returned from blockchain.info or
    similar services contain coin_value information that must be trusted
    on faith. Mistaken coin_value data can result in coins being wasted
    to fees.

    This function solves this problem by iterating over the incoming
    transactions, fetching them from the tx_db in full, and verifying
    that the coin_values are as expected.

    Returns the fee for this transaction. If any of the spendables set by
    tx.set_unspents do not match the authenticated transactions, a
    BadSpendableError is raised.
    """
    tx_hashes = set((tx_in.previous_hash for tx_in in tx.txs_in))

    # build a local copy of the DB
    tx_lookup = {}
    for h in tx_hashes:
        the_tx = tx_db.get(h)
        if the_tx is None:
            raise KeyError("hash id %s not in tx_db" % b2h_rev(h))
        if the_tx.hash() != h:
            raise ValueError("attempt to load Tx %s yield a Tx with id %s" % (h2b_rev(h), the_tx.id()))
        tx_lookup[h] = the_tx

    for idx, tx_in in enumerate(tx.txs_in):
        if tx_in.previous_hash not in tx_lookup:
            raise KeyError("hash id %s not in tx_lookup" % b2h_rev(tx_in.previous_hash))
        txs_out = tx_lookup[tx_in.previous_hash].txs_out
        if tx_in.previous_index > len(txs_out):
            raise ValueError("tx_out index %d is too big for Tx %s" %
                (tx_in.previous_index, b2h_rev(tx_in.previous_hash)))
        tx_out1 = txs_out[tx_in.previous_index]
        tx_out2 = tx.unspents[idx]
        if tx_out1.coin_value != tx_out2.coin_value:
            raise BadSpendableError(
                "unspents[%d] coin value mismatch (%d vs %d)" % (idx, tx_out1.coin_value, tx_out2.coin_value))
        if tx_out1.script != tx_out2.script:
            raise BadSpendableError("unspents[%d] script mismatch!" % idx)

    return tx.fee()
