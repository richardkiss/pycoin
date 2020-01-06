from ..convention import tx_fee


class SecretExponentMissing(Exception):
    pass


def create_tx(network, spendables, payables, fee="standard", lock_time=0, version=1):
    """
    This function provides the easiest way to create an unsigned transaction.

    All coin values are in satoshis.

    :param spendables: a list of Spendable objects, which act as inputs.
        Each item in the list can be a Spendable, or text from Spendable.as_text,
        or a dictionary from Spendable.as_dict (which might be easier for
        airgapped transactions, for example).
    :param payables: a list where each entry is a address, or a tuple of
        (address, coin_value). If the coin_value is missing or
        zero, this address is thrown into the "split pool". Funds not
        explicitly claimed by the fee or an address are shared as
        equally as possible among the split pool. All coins are consumed:
        if the amount to be split does not divide evenly, some of the earlier
        addresses will get an extra satoshi.
    :param fee: an integer, or the (deprecated) string "standard" for it to be calculated
    :param version: (optional) the version to use in the transaction. Defaults to 1.
    :param lock_time: (optional) the lock_time to use in the transaction. Defaults to 0.
    :return: :class:`Tx <Tx>` object, with unspents populated
    :rtype: pycoin.tx.Tx.Tx

    Usage::

        >>> spendables = spendables_for_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        >>> tx = create_tx(network, spendables, ["1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"], fee=0)

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
            address, coin_value = payable
        else:
            address = payable
            coin_value = 0
        script = network.contract.for_address(address)
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


def sign_tx(network, tx, wifs=[], **kwargs):
    """
    :param tx: a transaction
    :param wifs: the list of WIFs required to sign this transaction.
    :return: :class:`Tx <Tx>` object, modified in place

    This is a convenience function used to sign a transaction.
    The transaction must have "unspents" set by, for example, calling tx.unspents_from_db.

    Returns the signed Tx transaction, or raises an exception.

    Usage::

        >> sign_tx(network, tx, wifs=["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"])
    """
    keychain = network.keychain()
    keychain.add_secrets((network.parse.wif(_) for _ in wifs))
    solver = tx.Solver(tx)
    solver.sign(keychain, **kwargs)


def create_signed_tx(network, spendables, payables, wifs=[], fee="standard",
                     lock_time=0, version=1, **kwargs):
    """
    This convenience function calls :func:`create_tx` and :func:`sign_tx` in turn. Read the documentation
    for those functions for information on the parameters.

    Usage::

        >>> spendables = spendables_for_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        >>> wifs = ["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"]
        >>> payables = ["1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"]
        >>> tx = create_signed_tx(network, spendables, payables, wifs=wifs, fee=0)

    This will move all available reported funds from 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    to 1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP, with no transaction fees (which means it might
    take a while to confirm, possibly never).
    """

    tx = create_tx(network, spendables, payables, fee=fee, lock_time=lock_time, version=version)
    sign_tx(network, tx, wifs=wifs, **kwargs)
    for idx, tx_out in enumerate(tx.txs_in):
        if not tx.is_solution_ok(idx):
            raise SecretExponentMissing("failed to sign spendable for %s" %
                                        tx.unspents[idx])
    return tx
