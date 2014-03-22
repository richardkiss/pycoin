from bitcoinrpc.authproxy import AuthServiceProxy

# This file creates an external dependancy on bitcoinrpc
# Do not import this file unless you:
# 1) Have bitcoinrpc installed and
# 2) Need to query bitcoind

# If functions in this file are imported in other files, the imports should be
# inside the function call so that the dependancy doesn't cause issues


def get_bitcoind_conn(bitcoind_url):
    return AuthServiceProxy(bitcoind_url)


def get_tx_hex_from_id(tx_id, bitcoind_conn):
    '''
    Requires txindex=1 in your bitcoin.conf file
    '''
    return bitcoind_conn.getrawtransaction(tx_id)


def decode_tx_hex(tx_hex, bitcoind_conn):
    '''
    Decode the transaction with bitcoind and confirm the inputs/outputs match
    '''
    return bitcoind_conn.decoderawtransaction(tx_hex)
