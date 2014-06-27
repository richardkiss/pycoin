
from ..encoding import wif_to_secret_exponent
from ..convention import tx_fee

from .Spendable import Spendable
from .Tx import Tx
from .TxOut import TxOut, standard_tx_out_script
from .pay_to import build_hash160_lookup

class SecretExponentMissing(Exception):
    pass


class LazySecretExponentDB(object):
    """
    The pycoin pure python implementation that converts secret exponents
    into public pairs is very slow, so this class does the conversion lazily
    and caches the results to optimize for the case of a large number
    of secret exponents.
    """
    def __init__(self, wif_iterable, secret_exponent_db_cache):
        self.wif_iterable = iter(wif_iterable)
        self.secret_exponent_db_cache = secret_exponent_db_cache

    def get(self, v):
        if v in self.secret_exponent_db_cache:
            return self.secret_exponent_db_cache[v]
        for wif in self.wif_iterable:
            secret_exponent = wif_to_secret_exponent(wif)
            d = build_hash160_lookup([secret_exponent])
            self.secret_exponent_db_cache.update(d)
            if v in self.secret_exponent_db_cache:
                return self.secret_exponent_db_cache[v]
        self.wif_iterable = []
        return None


def create_tx(spendables, payables, fee="standard", lock_time=0, version=1):
    """
    This function provides the easiest way to create an unsigned transaction.

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
    fee:
        a value, or "standard" for it to be calculated.
    version:
        the version to use in the transaction. Normally 1.
    lock_time:
        the lock_time to use in the transaction. Normally 0.

    Returns the unsigned Tx transaction. Note that unspents are set, so the
    transaction can be immediately signed.

    Example:

    tx = create_tx(
        spendables_for_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ["1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"],
        fee=0)

    This will move all available reported funds from 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    to 1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP, with no transaction fees (which means it might
    take a while to confirm, possibly never).
    """

    def _fix_spendable(s):
        if isinstance(s, Spendable):
            return s
        if not hasattr(s, "keys"):
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
        script = standard_tx_out_script(bitcoin_address)
        txs_out.append(TxOut(coin_value, script))

    tx = Tx(version=version, txs_in=txs_in, txs_out=txs_out, lock_time=lock_time)
    tx.set_unspents(spendables)

    distribute_from_split_pool(tx, fee)
    return tx


def distribute_from_split_pool(tx, fee):
    """
    This function looks at TxOut items of a transaction tx and
    and puts TxOut items with a coin value of zero into a "split pool".
    Funds not explicitly claimed by the fee or other TxOut items are
    shared as equally as possible among the split pool. If the amount
    to be split does not divide evenly, some of the earlier TxOut items
    will get an extra satoshi.
    tx:
        the transaction
    fee:
        the reserved fee set aside
    """

    # calculate fees
    if fee == 'standard':
        # TODO: improve this
        # 1: the tx is not fully built out, so it will actually be larger than implied at this point
        # 2: recommended_fee_for_tx gives estimates that are too high
        fee = tx_fee.recommended_fee_for_tx(tx)

    zero_count = sum(1 for tx_out in tx.txs_out if tx_out.coin_value == 0)
    if zero_count > 0:
        total_coin_value = sum(spendable.coin_value for spendable in tx.txs_in_as_spendable())
        coins_allocated = sum(tx_out.coin_value for tx_out in tx.txs_out) + fee
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
    return zero_count


def sign_tx(tx, wifs=[], secret_exponent_db={}):
    """
    This function provides an convenience method to sign a transaction.

    The transaction must have "unspents" set by, for example,
    calling tx.unspents_from_db.

    wifs:
        the list of WIFs required to sign this transaction.
    secret_exponent_db:
        an optional dictionary (or any object with a .get method) that contains
        a bitcoin address => (secret_exponent, public_pair, is_compressed)
        tuple. This will be built automatically lazily with the list of WIFs.
        You can pass in an empty dictionary and as WIFs are processed, they
        will be cached here. If you have multiple transactions to sign, each with
        the same WIF list, passing a cache dictionary in may speed things up a bit.

    Returns the signed Tx transaction, or raises an exception.

    At least one of "wifs" and "secret_exponent_db" must be included for there
    to be any hope of signing the transaction.

    Example:

    sign_tx(wifs=["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"])
    """
    tx.sign(LazySecretExponentDB(wifs, secret_exponent_db))


def create_signed_tx(spendables, payables, wifs=[], fee="standard",
                     lock_time=0, version=1, secret_exponent_db={}):
    """
    This function provides an easy way to create and sign a transaction.

    All coin values are in satoshis.

    spendables, payables, fee, lock_time, version are as in create_tx, above.
    wifs, secret_exponent_db are as in sign_tx, above.

    Returns the signed Tx transaction, or raises an exception.

    At least one of "wifs" and "secret_exponent_db" must be included for there
    to be any hope of signing the transaction.

    Example:

    tx = create_signed_tx(
        spendables_for_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ["1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"],
        wifs=["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"],
        fee=0)

    This will move all available reported funds from 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    to 1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP, with no transaction fees (which means it might
    take a while to confirm, possibly never).
    """

    tx = create_tx(spendables, payables, fee=fee, lock_time=lock_time, version=version)
    sign_tx(tx, wifs=wifs, secret_exponent_db=secret_exponent_db)
    for idx, tx_out in enumerate(tx.txs_in):
        if not tx.is_signature_ok(idx):
            raise SecretExponentMissing("failed to sign spendable for %s" %
                                        tx.unspents[idx].bitcoin_address())
    return tx
