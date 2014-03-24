from bitcoinrpc.authproxy import AuthServiceProxy
from pycoin.convention import btc_to_satoshi, satoshi_to_btc

from collections import defaultdict

# This file creates an external dependancy on bitcoinrpc
# Do not import this file unless you:
# 1) Have bitcoinrpc installed and
# 2) Need to query bitcoind

# If functions in this file are imported in other files, the imports should be
# inside the function call so that the dependancy doesn't cause issues


def get_bitcoind_conn(bitcoind_url):
    '''
    Returns a bitcoind connection that can be used for the functions below
    a bitcoind url might look like this:
    http://username:password@127.0.0.1:8332/
    '''
    return AuthServiceProxy(bitcoind_url)


def get_tx_hex_from_id(tx_id, bitcoind_conn):
    '''
    Requires txindex=1 in your bitcoin.conf file
    '''
    #print('Hitting bitcoind tx_index for %s...' % tx_id)
    return bitcoind_conn.getrawtransaction(tx_id)


def decode_tx_hex(tx_hex, bitcoind_conn):
    '''
    Decode the transaction with bitcoind and confirm the inputs/outputs match
    '''
    #print('Decoding tx_hex with bitcoind...')
    return bitcoind_conn.decoderawtransaction(tx_hex)


def get_and_decode_tx_from_id(tx_id, bitcoind_conn):
    tx_hex = get_tx_hex_from_id(tx_id, bitcoind_conn)
    return decode_tx_hex(tx_hex, bitcoind_conn)


def parse_decoded_tx(decoded_tx, vout_num):
    '''
    Take a decoded transaction and return the address and satoshis available

    TODO: add support for more than just pay to pubkey
    '''
    vouts = []
    for vout_entry in decoded_tx['vout']:
        if vout_entry['n'] == vout_num:
            satoshis = btc_to_satoshi(vout_entry['value'])
            # TODO: only supports pay to pubkey
            address = vout_entry['scriptPubKey']['addresses'][0]
            vouts.append((satoshis, address))

    err_msg = 'Tx has no vout #%s: %s' % (vout_num, decoded_tx)
    assert len(vouts) != 0, err_msg

    err_msg = 'Tx has >1 vout with #%s: %s' % (vout_num, decoded_tx)
    assert len(vouts) == 1, err_msg

    return vouts[0]


def get_tx_inputs_and_outputs(tx_hex, bitcoind_conn):
    '''
    Take a TX hex from pycoin, decode it with bitcoind and return the
    inputs/ouputs you can use to make sure they match what you expect before
    broadcasting.

    http://www.wildbunny.co.uk/blog/2014/03/18/watch_only_wallet/
    '''

    decoded_tx = decode_tx_hex(tx_hex, bitcoind_conn)

    inputs, outputs = [], []

    for vin_entry in decoded_tx['vin']:

        prev_tx_id = vin_entry['txid']
        prev_vout = vin_entry['vout']

        # get previous transaction outputs from bitcoind
        prev_tx_decoded = get_and_decode_tx_from_id(prev_tx_id, bitcoind_conn)
        prev_satoshis, prev_address = parse_decoded_tx(
            decoded_tx=prev_tx_decoded, vout_num=prev_vout)

        inputs.append((prev_satoshis, prev_address))

    for vout_entry in decoded_tx['vout']:
        # TODO: only supports pay to pubkey
        address = vout_entry['scriptPubKey']['addresses'][0]
        satoshis = btc_to_satoshi(vout_entry['value'])
        outputs.append((satoshis, address))

    return inputs, outputs


def calc_tx_value_summary(inputs, outputs):
    input_satoshis = sum([x[0] for x in inputs])
    output_satoshis = sum([x[0] for x in outputs])
    return input_satoshis, output_satoshis


def group_tx_inputs(inputs, outputs):
    input_dd = defaultdict(long)
    for input_satoshis, input_address in inputs:
        input_dd[input_address] += input_satoshis

    output_dd = defaultdict(long)
    for output_satoshis, output_address in outputs:
        output_dd[output_address] += output_satoshis

    return input_dd, output_dd


def summarize_tx(inputs, outputs):
    input_dd, output_dd = group_tx_inputs(inputs, outputs)
    total_input_satoshis, total_output_satoshis = calc_tx_value_summary(
        inputs, outputs)
    tx_fee_satoshis = total_input_satoshis-total_output_satoshis

    return {'input_summary': input_dd,
            'output_summary': output_dd,
            'tx_fee_satoshis': tx_fee_satoshis,
            'total_satoshis_sent': total_input_satoshis,
            'total_satoshis_recieved': total_output_satoshis,
            }


def format_satoshis(satoshis):
    return '%s BTC (%s satoshis)' % (satoshi_to_btc(satoshis), satoshis)


def print_summary(tx_summary):
    for address, satoshis in tx_summary['input_summary'].iteritems():
        print('Address %s sending %s' % (address, format_satoshis(satoshis)))
    for address, satoshis in tx_summary['output_summary'].iteritems():
        print('Address %s recieving %s' % (address, format_satoshis(satoshis)))
    print('Total Sent: %s' % format_satoshis(
        tx_summary['total_satoshis_sent']))
    print('Total Recieved: %s' % format_satoshis(
        tx_summary['total_satoshis_recieved']))
    print('TX Fee: %s' % format_satoshis(tx_summary['tx_fee_satoshis']))
