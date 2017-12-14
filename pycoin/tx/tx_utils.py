
from pycoin.coins.bitcoin.networks import BitcoinMainnet

from ..convention import tx_fee

from ..solve.utils import build_hash160_lookup


class SecretExponentMissing(Exception):
    pass


class LazySecretExponentDB(object):
    """
    The pycoin pure python implementation that converts secret exponents
    into public pairs is very slow, so this class does the conversion lazily
    and caches the results to optimize for the case of a large number
    of secret exponents.
    """
    def __init__(self, wif_iterable, secret_exponent_db_cache, generators, network=BitcoinMainnet):
        self._wif_iterable = iter(wif_iterable)
        self._secret_exponent_db_cache = secret_exponent_db_cache
        self._generators = generators
        self._network = network

    def get(self, v):
        if v in self._secret_exponent_db_cache:
            return self._secret_exponent_db_cache[v]
        for wif in self._wif_iterable:
            key = self._network.ui.parse(wif, types=["key"])
            if key is None:
                continue
            secret_exponent = key.secret_exponent()
            if secret_exponent is None:
                continue
            d = build_hash160_lookup([secret_exponent], self._generators)
            self._secret_exponent_db_cache.update(d)
            if v in self._secret_exponent_db_cache:
                return self._secret_exponent_db_cache[v]
        self._wif_iterable = []
        return None


def create_tx(spendables, payables, fee="standard", lock_time=0, version=1, network=BitcoinMainnet):
    """
    This function provides the easiest way to create an unsigned transaction.

    All coin values are in satoshis.

    :param spendables: a list of Spendable objects, which act as inputs.
        Each item in the list can be a Spendable, or text from Spendable.as_text,
        or a dictionary from Spendable.as_dict (which might be easier for
        airgapped transactions, for example).
    :param payables: a list where each entry is a bitcoin address, or a tuple of
        (bitcoin address, coin_value). If the coin_value is missing or
        zero, this address is thrown into the "split pool". Funds not
        explicitly claimed by the fee or a bitcoin address are shared as
        equally as possible among the split pool. All coins are consumed:
        if the amount to be split does not divide evenly, some of the earlier
        bitcoin addresses will get an extra satoshi.
    :param fee: an integer, or the (deprecated) string "standard" for it to be calculated
    :param version: (optional) the version to use in the transaction. Defaults to 1.
    :param lock_time: (optional) the lock_time to use in the transaction. Defaults to 0.
    :return: :class:`Tx <Tx>` object, with unspents populated
    :rtype: pycoin.tx.Tx.Tx

    Usage::

        >>> spendables = spendables_for_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        >>> tx = create_tx(spendables, ["1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"], fee=0)

    This will move all available reported funds from 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    to 1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP, with no transaction fees (which means it might
    take a while to confirm, possibly never).
    """

    Tx = network.tx

    def _fix_spendable(s):
        if isinstance(s, Tx.Spendable):
            return s
        if not hasattr(s, "keys"):
            return Tx.Spendable.from_text(s)
        return Tx.Spendable.from_dict(s)

    spendables = [_fix_spendable(s) for s in spendables]
    txs_in = [spendable.tx_in() for spendable in spendables]

    txs_out = []
    for payable in payables:
        if len(payable) == 2:
            bitcoin_address, coin_value = payable
        else:
            bitcoin_address = payable
            coin_value = 0
        script = network.ui.script_for_address(bitcoin_address)
        txs_out.append(Tx.TxOut(coin_value, script))

    tx = Tx(version=version, txs_in=txs_in, txs_out=txs_out, lock_time=lock_time)
    tx.set_unspents(spendables)

    distribute_from_split_pool(tx, fee)
    return tx


def split_with_remainder(total_amount, split_count):
    value_each, extra_count = divmod(total_amount, split_count)
    for _ in range(extra_count):
        yield value_each + 1
    for _ in range(split_count-extra_count):
        yield value_each


def distribute_from_split_pool(tx, fee):
    """
    :param tx: a transaction
    :param fee: integer, satoshi value to set aside for transaction fee

    This function looks at TxOut items of a transaction tx and
    and puts TxOut items with a coin value of zero into a "split pool".
    Funds not explicitly claimed by the fee or other TxOut items are
    shared as equally as possible among the split pool. If the amount
    to be split does not divide evenly, some of the earlier TxOut items
    will get an extra satoshi. This function modifies `tx` in place.
    """

    # calculate fees
    if fee == 'standard':
        # TODO: improve this
        # 1: the tx is not fully built out, so it will actually be larger than implied at this point
        # 2: recommended_fee_for_tx gives estimates that are too high
        fee = tx_fee.recommended_fee_for_tx(tx)

    zero_txs_out = [tx_out for tx_out in tx.txs_out if tx_out.coin_value == 0]
    zero_count = len(zero_txs_out)
    if zero_count > 0:
        total_coin_value = sum(spendable.coin_value for spendable in tx.unspents)
        coins_allocated = sum(tx_out.coin_value for tx_out in tx.txs_out) + fee
        remaining_coins = total_coin_value - coins_allocated
        if remaining_coins < 0:
            raise ValueError("insufficient inputs for outputs")
        if remaining_coins < zero_count:
            raise ValueError("not enough to pay nonzero amounts to at least one of the unspecified outputs")
        for value, tx_out in zip(split_with_remainder(remaining_coins, zero_count), zero_txs_out):
            tx_out.coin_value = value
    return zero_count


def sign_tx(tx, wifs=[], secret_exponent_db=None, network=BitcoinMainnet, **kwargs):
    """
    :param tx: a transaction
    :param wifs: the list of WIFs required to sign this transaction.
    :param secret_exponent_db: (optional) a dictionary (or any object with a .get method) that contains
        a bitcoin address => (secret_exponent, public_pair, is_compressed) tuple lookup.
        This will be built automatically lazily with the list of WIFs.
        You can pass in an empty dictionary and as WIFs are processed, they
        will be cached here. If you have multiple transactions to sign, each with
        the same WIF list, passing a cache dictionary in may speed things up a bit.
    :return: :class:`Tx <Tx>` object, modified in place

    This is a convenience function used to sign a transaction.
    The transaction must have "unspents" set by, for example, calling tx.unspents_from_db.

    Returns the signed Tx transaction, or raises an exception.

    At least one of "wifs" and "secret_exponent_db" must be included for there
    to be any hope of signing the transaction.

    Usage::

        >> sign_tx(tx, wifs=["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"])
    """
    secret_exponent_db = secret_exponent_db or {}
    solver = tx.Solver(tx)
    solver.sign(LazySecretExponentDB(wifs, secret_exponent_db, tx.SolutionChecker.generators, network), **kwargs)


def create_signed_tx(spendables, payables, wifs=[], fee="standard",
                     lock_time=0, version=1, secret_exponent_db={},
                     netcode='BTC', network=BitcoinMainnet, **kwargs):
    """
    This convenience function calls :func:`create_tx` and :func:`sign_tx` in turn. Read the documentation
    for those functions for information on the parameters.

    Usage::

        >>> spendables = spendables_for_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        >>> wifs = ["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"]
        >>> payables = ["1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"]
        >>> tx = create_signed_tx(spendables, payables, wifs=wifs, fee=0)

    This will move all available reported funds from 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    to 1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP, with no transaction fees (which means it might
    take a while to confirm, possibly never).
    """

    tx = create_tx(spendables, payables, fee=fee, lock_time=lock_time, version=version, network=network)
    sign_tx(tx, wifs=wifs, secret_exponent_db=secret_exponent_db,
            netcode=netcode, **kwargs)
    for idx, tx_out in enumerate(tx.txs_in):
        if not tx.is_signature_ok(idx):
            raise SecretExponentMissing("failed to sign spendable for %s" %
                                        tx.unspents[idx].bitcoin_address())
    return tx
