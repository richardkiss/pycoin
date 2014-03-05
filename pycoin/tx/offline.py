#!/usr/bin/env python

import io
import binascii
import operator

from pycoin.services.blockchain_info import (coin_sources_for_unspent_outputs,
        unspent_outputs_for_address)
from pycoin.tx import UnsignedTx, SecretExponentSolver
from pycoin.encoding import wif_to_secret_exponent
from pycoin.convention.tx_fee import recommended_fee_for_tx

def satoshis_to_recieve(destination_instructions):
    satoshis = 0
    for amount, address in destination_instructions:
        msg = '%s is not an int' % amount
        assert type(amount) is int, msg
        satoshis += amount
    return satoshis

def satoshis_to_send(coin_sources):
    satoshis = 0
    for tx_hash, tx_output_index, tx_out in coin_sources:
        msg = '%s is not an int' % tx_out.coin_value
        assert type(tx_out.coin_value) is int, msg
        satoshis += tx_out.coin_value
    return satoshis

def generate_offline_data(source_addresses):
    '''
    `source_addresses` is a list in the following form:

        ('source_address1', 'source_address2', 'source_address3', )
    '''

    unspent_outputs = []
    for address in source_addresses:
        unspent_outputs.extend(unspent_outputs_for_address(address))
    return unspent_outputs

def sign_transaction_offline(unspent_outputs, wifs, coins_to, expected_fee):
    """
    Run this on an offline computer.

    Unspent outputs are generated from `generate_offline_data`, but you could
    write your own function to generate these unspent outputs.

    Outputs will be fully spent, so if you want to have a change address you
    should specify it as a destination address.

    `wifs` is a list of wifs: ('wif1', 'wif2', 'wif3')

    `coins_to` are a list of the following form:
        (
            # satoshis_to_recieve, dest_address
            (24214234, 'dest_address1'),
            (89345029, 'dest_address2'),
            (9384389, 'dest_address3'),
            # etc
        )

    `expected_fee` is the transaction fee (what's left over) in satoshis. This
    is not strictly neccessary but added as a defensive check.

    # TODO: recommend a TX fee
    """

    assert type(expected_fee) is int, '%s is not an int' % expected_fee

    coins_from = coin_sources_for_unspent_outputs(unspent_outputs)
    to_spend = satoshis_to_send(coins_from)

    implied_fee = satoshis_to_send(coins_from) - satoshis_to_recieve(coins_to)

    msg = '%s != %s' % (implied_fee, expected_fee)
    assert implied_fee == expected_fee, msg

    secret_exponents = []
    for wif in wifs:
        secret_exponents.append(wif_to_secret_exponent(wif))

    unsigned_tx = UnsignedTx.standard_tx(coins_from, coins_to)
    solver = SecretExponentSolver(secret_exponents)
    new_tx = unsigned_tx.sign(solver)
    s = io.BytesIO()
    new_tx.stream(s)
    tx_bytes = s.getvalue()
    tx_hex = binascii.hexlify(tx_bytes).decode("utf8")

    # Weak fee checking
    recommended_fee = recommended_fee_for_tx(new_tx)
    msg = '%s fee is too high (%s recommended)' % (implied_fee, recommended_fee)
    assert implied_fee < 2*recommended_fee, msg
    msg = '%s fee is too low (%s recommended)' % (implied_fee, recommended_fee)
    assert 2*implied_fee > recommended_fee, msg

    # You can broadcast at http://blockchain.info/pushtx
    return tx_hex

