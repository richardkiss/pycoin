import binascii

from ..convention import tx_fee
from ..ecdsa import generator_secp256k1, verify as ecdsa_verify
from ..encoding import public_pair_to_bitcoin_address, sec_to_public_pair
from ..encoding import wif_to_secret_exponent
from ..networks import address_prefix_for_netcode
from ..serialize import b2h_rev, h2b

from .Spendable import Spendable
from .Tx import Tx
from .TxOut import TxOut
from .pay_to import build_hash160_lookup, script_obj_from_script, ScriptMultisig, ScriptPayToAddress, ScriptPayToPublicKey
from ..networks import wif_prefix_for_netcode
from ..ui import standard_tx_out_script
from .script.check_signature import parse_signature_blob
from .script.tools import opcode_list


class SecretExponentMissing(Exception):
    pass


class NoAddressesForScriptTypeError(Exception):
    pass


class LazySecretExponentDB(object):
    """
    The pycoin pure python implementation that converts secret exponents
    into public pairs is very slow, so this class does the conversion lazily
    and caches the results to optimize for the case of a large number
    of secret exponents.
    """
    def __init__(self, wif_iterable, secret_exponent_db_cache, netcode='BTC'):
        self.wif_iterable = iter(wif_iterable)
        self.secret_exponent_db_cache = secret_exponent_db_cache
        self.netcode = netcode

    def get(self, v):
        if v in self.secret_exponent_db_cache:
            return self.secret_exponent_db_cache[v]
        for wif in self.wif_iterable:
            secret_exponent = wif_to_secret_exponent(
                wif, allowable_wif_prefixes=wif_prefix_for_netcode(self.netcode))
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
        total_coin_value = sum(spendable.coin_value for spendable in tx.unspents)
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


def sign_tx(tx, wifs=[], secret_exponent_db={}, netcode='BTC', **kwargs):
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
    tx.sign(LazySecretExponentDB(wifs, secret_exponent_db, netcode), **kwargs)


def create_signed_tx(spendables, payables, wifs=[], fee="standard",
                     lock_time=0, version=1, secret_exponent_db={},
                     netcode='BTC', **kwargs):
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
    sign_tx(tx, wifs=wifs, secret_exponent_db=secret_exponent_db,
            netcode=netcode, **kwargs)
    for idx, tx_out in enumerate(tx.txs_in):
        if not tx.is_signature_ok(idx):
            raise SecretExponentMissing("failed to sign spendable for %s" %
                                        tx.unspents[idx].bitcoin_address())
    return tx

def who_signed_tx(tx, tx_in_idx, netcode='BTC'):
    """
    Given a transaction (tx) an input index (tx_in_idx), attempt to figure
    out which addresses where used in signing (so far). This method
    depends on tx.unspents being properly configured. This should work on
    partially-signed MULTISIG transactions (it will return as many
    addresses as there are good signatures).

    Returns a list of ( address, sig_type ) pairs.

    Raises NoAddressesForScriptTypeError if addresses cannot be determined
    for the input's script.

    TODO: This does not yet support P2SH.
    """
    tx_in = tx.txs_in[tx_in_idx]
    tx_in_opcode_list = opcode_list(tx_in.script)
    parent_tx_id = b2h_rev(tx_in.previous_hash)
    parent_tx_out_idx = tx_in.previous_index
    parent_tx_out_script = tx.unspents[tx_in_idx].script
    script_obj = script_obj_from_script(parent_tx_out_script)
    signed_by = []

    if script_obj is None:
        script_obj_info = {}
    else:
        script_obj_info = script_obj.info(netcode=netcode)

    if type(script_obj) in ( ScriptPayToAddress, ScriptPayToPublicKey ):
        if tx.is_signature_ok(tx_in_idx):
            addr = script_obj_info.get('address')
            _, sig_type = parse_signature_blob(h2b(tx_in_opcode_list[0]))
            signed_by.append(( addr, sig_type ))
    elif type(script_obj) is ScriptMultisig:
        for opcode in tx_in_opcode_list[1:]:
            try:
                sig_pair, sig_type = parse_signature_blob(h2b(opcode))
            except ( TypeError, binascii.Error ):
                continue

            sig_hash = tx.signature_hash(parent_tx_out_script, parent_tx_out_idx, sig_type)

            for sec_key in script_obj.sec_keys:
                public_pair = sec_to_public_pair(sec_key)

                if ecdsa_verify(generator_secp256k1, public_pair, sig_hash, sig_pair):
                    addr_pfx = address_prefix_for_netcode(netcode)
                    addr = public_pair_to_bitcoin_address(public_pair, address_prefix=addr_pfx)
                    signed_by.append(( addr, sig_type ))
    else:
        raise NoAddressesForScriptTypeError('unable to determine signing addresses for script type of parent tx {}[{}]'.format(parent_tx_id, parent_tx_out_idx))

    return signed_by
