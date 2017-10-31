#!/usr/bin/env python

# this script runs a server that queues up transactions to be signed by the rpi_signer

import json

from http.server import test, BaseHTTPRequestHandler

from pycoin.key.BIP32Node import BIP32Node
from pycoin.serialize import b2h
from pycoin.tx import tx_utils
from pycoin.tx.Tx import Tx


def unsigned_tx_q():
    P1 = "0/1/5"
    P2 = "0/1/6"

    bip32node = BIP32Node.from_master_secret(b'foo')

    sec = bip32node.subkey_for_path(P1).sec()
    coinbase_tx = Tx.coinbase_tx(sec, 5000000000)
    spendables = coinbase_tx.tx_outs_as_spendable()
    payables = [bip32node.subkey_for_path(P2).address()]
    tx = tx_utils.create_tx(spendables, payables)

    def bip32node_info_for_address(address):
        return bip32node.fingerprint(), P1

    key_paths = []
    r = dict(tx_hex=tx.as_hex(include_unspents=True), key_paths=key_paths, id=tx.id())
    for unspent in tx.unspents:
        address = unspent.address()
        bip32_fingerprint, path = bip32node_info_for_address(address)
        key_paths.append(dict(key_fingerprint=b2h(bip32_fingerprint), key_path=path))

    return [r]


def process_signed_tx(tx, btx_id):
    # in this example, btx_id is set to tx.id(), but it can be any string
    # it's usually some kind of primary key
    print("got signed tx with id %s" % tx.id())


TX_Q = unsigned_tx_q()


class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        """Serve a GET request."""
        self.send_response(200)
        self.send_header("Content-type", "Application/JSON")
        self.end_headers()

        r = []
        if len(TX_Q) > 0:
            r.append(TX_Q.pop())

        output = json.dumps(r).encode("utf8")
        self.wfile.write(output)

    def do_POST(self):
        """Serve a POST request."""
        length = int(self.headers.get("content-length"))
        blob = self.rfile.read(length)
        d = json.loads(blob.decode("utf8"))
        btx_id = d.get("btx_id")
        tx = Tx.from_hex(d.get("btx_hex"))
        process_signed_tx(tx, btx_id)
        self.send_response(200)
        self.end_headers()


def main():
    test(HandlerClass=RequestHandler)


if __name__ == '__main__':
    main()
