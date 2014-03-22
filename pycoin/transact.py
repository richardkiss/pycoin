import binascii
import StringIO
import io
import codecs

from pycoin.encoding import wif_to_secret_exponent
from pycoin.convention import tx_fee, satoshi_to_btc
from pycoin.services.blockrio import unspent_outputs_from_address
from pycoin.serialize import h2b_rev, stream_to_bytes
from pycoin.tx.TxIn import TxIn
from pycoin.tx.TxOut import TxOut, standard_tx_out_script
from pycoin.tx.script.solvers import build_hash160_lookup_db
from pycoin.tx import Tx
from pycoin.tx.airgap import minimal_tx_db_for_txs_out

from pycoin.scripts.check_tx import bitcoind_signrawtransaction, tx_db_for_tx


def check_fees(unsigned_tx, tx_db):
    total_in = unsigned_tx.total_in(tx_db)
    total_out = unsigned_tx.total_out()
    actual_tx_fee = total_in - total_out
    recommended_tx_fee = tx_fee.recommended_fee_for_tx(unsigned_tx)
    if actual_tx_fee > recommended_tx_fee:
        print("warning: %s transaction fee exceeds %s BTC recommendation." %
              (satoshi_to_btc(actual_tx_fee),
                  satoshi_to_btc(recommended_tx_fee)))
    elif actual_tx_fee < 0:
        print("not enough source coins (%s BTC) for destination (%s BTC)."
              " Short %s BTC" %
              (satoshi_to_btc(total_in),
               satoshi_to_btc(total_out), satoshi_to_btc(-actual_tx_fee)))
    elif actual_tx_fee < recommended_tx_fee:
        print("warning: transaction fee lower than (casually calculated)"
              " expected value of %s BTC, transaction might not propogate" %
              satoshi_to_btc(recommended_tx_fee))

    assert total_out != 0, 'This whole tx is going to miners!'
    return actual_tx_fee


def get_unsigned_tx(tx_inputs, tx_outputs):
    tx_db = {}
    outgoing_txs_out = []
    txs_in = []
    txs_out = []
    for tx_hash_hex, tx_output_index_decimal, tx_out_script_hex, \
            tx_out_coin_val in tx_inputs:
        tx_hash = h2b_rev(tx_hash_hex)
        tx_output_index = int(tx_output_index_decimal)
        txs_in.append(TxIn(tx_hash, tx_output_index))
        tx_out_script = binascii.unhexlify(tx_out_script_hex)
        outgoing_txs_out.append(TxOut(tx_out_coin_val, tx_out_script))

    for address, amount in tx_outputs:
        txs_out.append(TxOut(amount, standard_tx_out_script(address)))

    unsigned_tx = Tx(version=1, txs_in=txs_in, txs_out=txs_out)
    tx_db = minimal_tx_db_for_txs_out(unsigned_tx, outgoing_txs_out)
    return unsigned_tx, tx_db


def create_and_sign_tx_from_unspent_outputs(unspent_outputs, coins_to, wifs):
    '''
    Create and sign a transaction from unspent outputs.

    Can easibly be run on an airgap machine.

    coins_to is a list that takes the following form:
        (
            # dest_address, satoshis_to_recieve
            ('dest_address1', 24214234),
            ('dest_address2', 89345029),
            ('dest_address3', 9384389),
            # etc
        )

    '''

    # Defensive checks:
    assert type(wifs) is list, 'wif must be a list'

    unsigned_tx, tx_db = get_unsigned_tx(
        tx_inputs=unspent_outputs,
        tx_outputs=coins_to)
    actual_tx_fee = check_fees(unsigned_tx=unsigned_tx, tx_db=tx_db)
    assert actual_tx_fee > 0, 'Transaction fee of %s is <= 0' % actual_tx_fee

    print("transaction fee: %s BTC" % satoshi_to_btc(actual_tx_fee))

    secret_exponents = [wif_to_secret_exponent(pk) for pk in wifs]
    secret_exponent_lookup = build_hash160_lookup_db(secret_exponents)

    unsigned_before = unsigned_tx.bad_signature_count(tx_db)
    new_tx = unsigned_tx.sign(secret_exponent_lookup, tx_db)
    unsigned_after = unsigned_tx.bad_signature_count(tx_db)

    msg1 = '%d newly signed TxOut object(s)' % (unsigned_before-unsigned_after)
    msg2 = ' (%d unsigned before and %d unsigned now)' % (unsigned_before,
                                                          unsigned_after)
    print(msg1 + msg2)

    if unsigned_after == len(new_tx.txs_in):
        print("signing complete")

    tx_bytes = stream_to_bytes(new_tx.stream)

    # returns tx hex ready for broadcast
    return binascii.hexlify(tx_bytes).decode("utf8")


def create_and_sign_tx_from_address(source_address, coins_to, wifs):
    '''
    Create a signs a transaction to spend all coins in source addresses.

    Can only be run on an online machine.
    '''
    unspent_outputs = unspent_outputs_from_address(source_address)
    return create_and_sign_tx_from_unspent_outputs(
        unspent_outputs=unspent_outputs, coins_to=coins_to, wifs=wifs)


def tx_from_hex(tx_hex):
    '''
    Given a tx hex, return a Tx object.

    This is a hideously ugly workaround, but it's the easiest way to do this
    with how pycoin is structured.

    TODO: make this not terrible
    '''

    # Make a fake file object which is just a tx_hex
    temp = StringIO.StringIO()
    temp.write(tx_hex)
    temp.seek(0)

    f = io.BytesIO(codecs.getreader("hex_codec")(temp).read())
    return Tx.parse(f)


def test_tx_online(tx_hex, bitcoind_url):
    '''
    Use bitcoind to confirm the transaction won't be rejected by the network
    and also that pycoin thinks the signature is OK.

    Does not guarantee that the transaction is what you intended to sign, or
    that the fees are right. Those require separate checks.
    '''
    from pycoin.services.bitcoind import get_bitcoind_conn
    bitcoind_conn = get_bitcoind_conn(bitcoind_url)
    tx = tx_from_hex(tx_hex)
    tx_db = tx_db_for_tx(tx)
    signed = bitcoind_signrawtransaction(bitcoind_conn, tx, tx_db)
    is_ok = [tx.is_signature_ok(idx, tx_db) for idx in range(len(tx.txs_in))]

    err_msg = 'Expected a list of True, got %s instead' % is_ok
    assert all(is_ok), err_msg

    err_msg = 'Expected True, got %s instead' % signed.get("complete")
    assert signed.get("complete"), err_msg

    return True
