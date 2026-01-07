import unittest

from pycoin.symbols.tzec import network


class ZcashTestnetTest(unittest.TestCase):

    def test_network_info(self):
        """Test that the network has correct metadata"""
        self.assertEqual(network.symbol, "tZEC")
        self.assertEqual(network.network_name, "Zcash")
        self.assertEqual(network.subnet_name, "testnet")

    def test_address_generation(self):
        """Test that addresses are generated correctly and start with 'tm'"""
        # Test with a known secret exponent
        key = network.keys.private(secret_exponent=1)
        address = key.address()
        
        # Zcash testnet addresses should start with "tm"
        self.assertTrue(address.startswith('tm'), 
                       f"Expected testnet address to start with 'tm', got {address}")
        
        # Test another key
        key2 = network.keys.private(secret_exponent=12345)
        address2 = key2.address()
        self.assertTrue(address2.startswith('tm'),
                       f"Expected testnet address to start with 'tm', got {address2}")

    def test_wif_generation(self):
        """Test WIF generation for testnet"""
        key = network.keys.private(secret_exponent=1)
        wif = key.wif()
        
        # Parse the WIF back and verify it produces the same key
        parsed_key = network.parse.wif(wif)
        self.assertEqual(parsed_key.wif(), wif)
        self.assertEqual(parsed_key.address(), key.address())

    def test_bip32(self):
        """Test BIP32 key generation"""
        # Generate a BIP32 seed
        bip32_key = network.keys.bip32_seed(b"test seed")
        
        # Get the extended private and public keys
        xprv = bip32_key.hwif(as_private=1)
        xpub = bip32_key.hwif(as_private=0)
        
        # Verify they start with the correct prefixes for testnet
        self.assertTrue(xprv.startswith('tprv'),
                       f"Expected testnet BIP32 private key to start with 'tprv', got {xprv[:4]}")
        self.assertTrue(xpub.startswith('tpub'),
                       f"Expected testnet BIP32 public key to start with 'tpub', got {xpub[:4]}")
        
        # Verify address generation from BIP32
        address = bip32_key.address()
        self.assertTrue(address.startswith('tm'),
                       f"Expected BIP32 address to start with 'tm', got {address}")

    def test_parse_roundtrip(self):
        """Test that we can parse and regenerate keys"""
        # Create a key
        original_key = network.keys.private(secret_exponent=999)
        wif = original_key.wif()
        address = original_key.address()
        
        # Parse WIF
        parsed_key = network.parse.wif(wif)
        self.assertEqual(parsed_key.wif(), wif)
        self.assertEqual(parsed_key.address(), address)
        
        # Parse address
        parsed_address = network.parse.address(address)
        self.assertEqual(parsed_address.address(), address)


if __name__ == '__main__':
    unittest.main()
