import pytest
import unittest

from pycoin.encoding.bytes32 import to_bytes_32
from pycoin.encoding.hexbytes import h2b
from pycoin.symbols.grs import network as GroestlcoinMainnet


pytest.importorskip('groestlcoin_hash')


class GroestlcoinEncodingTestCase(unittest.TestCase):
    def test_p2pkh(self):
        def do_test(h160, address):
            self.assertEqual(GroestlcoinMainnet.address.for_p2pkh(h160), address)
            self.assertEqual(GroestlcoinMainnet.parse.p2pkh(address).address(), address)

        do_test(h2b('0000000000000000000000000000000000000000'), 'FVAiSujNZVgYSc27t6zUTWoKfAGxer42D4')

    def test_p2sh(self):
        def do_test(h160, redeem_script, address):
            self.assertEqual(GroestlcoinMainnet.contract.for_p2sh(h160), redeem_script)
            self.assertEqual(GroestlcoinMainnet.address.for_p2sh(h160), address)
            self.assertEqual(GroestlcoinMainnet.parse.p2sh(address).address(), address)

        do_test(
            h2b('2a84cf00d47f699ee7bbc1dea5ec1bdecb4ac154'),
            h2b('a9142a84cf00d47f699ee7bbc1dea5ec1bdecb4ac15487'), '35ZqQJcBQMZ1rsv8aSuJ2wkC7ohUFNJZ77')

    def test_wif(self):
        def do_test(sec_bytes, wif, address):
            parsed = GroestlcoinMainnet.parse.wif(wif)
            self.assertEqual(to_bytes_32(parsed.secret_exponent()), sec_bytes)
            self.assertEqual(parsed.wif(), wif)
            self.assertEqual(parsed.address(), address)

        do_test(
            h2b('0000000000000000000000000000000000000000000000000000000000000001'),
            '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAmVmAPb', 'FiT6218RsUiTMyG5DA8bDjrNNuofYV2MdF')
        do_test(
            h2b('0000000000000000000000000000000000000000000000000000000000000001'),
            'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sX6ptSt', 'Ffqz14cyvZYJavD76t6oHNDJnGiWcZMVxR')

    def test_bip32(self):
        xprv = ('xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmH'
                'ScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3GaoVXP')
        xpub = ('xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcY'
                'FgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJuY6NHg')
        parsed = GroestlcoinMainnet.parse.hierarchical_key(xprv)
        self.assertEqual(parsed.tree_depth(), 5)
        self.assertEqual(parsed.parent_fingerprint(), b'\xd8\x80\xd7\xd8')
        self.assertEqual(parsed.child_index(), 1000000000)
        self.assertEqual(parsed.chain_code(),
                         b'\xc7\x83\xe6{\x92\x1d+\xeb\x8fk8\x9c\xc6F\xd7&;AEp\x1d\xad\xd2\x16\x15H\xa8\xb0x\xe6^\x9e')
        self.assertEqual(parsed.secret_exponent(),
                         32162737660659799401901343156672072893797470137297259782459076395168682141640)
        self.assertEqual(parsed.hwif(as_private=True), xprv)
        self.assertEqual(parsed.hwif(as_private=False), xpub)

        self.assertEqual(parsed.wif(), 'Kybw8izYevo5xMh1TK7aUr7jHFCxXS1zv8p3oqFz3o2zFbjGCYKc')
        self.assertEqual(parsed.address(), 'FpjSHmYBamwxWSsPtaL2rUz98FSS17VmY2')
        self.assertEqual(parsed.wif(is_compressed=False), '5JMbvQZXHJAzJyoDnqWasGCwtiHJZivF2ckjn3n5mazYYwQHway')
        self.assertEqual(parsed.address(is_compressed=False), 'FrH6KqPfsLPHArqCJ8WciGyvnWcRmvAsHC')
