import unittest

from pycoin.symbols.stak import network as stak_network
from pycoin.symbols.tstak import network as tstak_network


class StakBip32Test(unittest.TestCase):
    """
    Test STRAKS BIP32 HD key derivation.
    
    These tests verify that BIP32 key derivation works correctly
    for STRAKS mainnet and testnet networks.
    """

    def test_stak_bip32_seed(self):
        """Test BIP32 key generation from a seed for STAK mainnet."""
        # Test with a simple seed
        master_key = stak_network.keys.bip32_seed(b"STRAKS test seed")
        
        # Verify we can derive the master key
        self.assertIsNotNone(master_key)
        self.assertIsNotNone(master_key.secret_exponent())
        
        # Verify we can get the BIP32 representation
        xprv = master_key.hwif(as_private=True)
        xpub = master_key.hwif(as_private=False)
        
        # STAK uses standard Bitcoin mainnet BIP32 prefixes (0488ade4/0488b21e)
        # which encode to xprv/xpub
        self.assertTrue(xprv.startswith('xprv'))
        self.assertTrue(xpub.startswith('xpub'))
        
        # Verify we can derive child keys
        child_key = master_key.subkey(0)
        self.assertIsNotNone(child_key)
        self.assertNotEqual(child_key.secret_exponent(), master_key.secret_exponent())

    def test_tstak_bip32_seed(self):
        """Test BIP32 key generation from a seed for tSTAK testnet."""
        # Test with a simple seed
        master_key = tstak_network.keys.bip32_seed(b"STRAKS testnet seed")
        
        # Verify we can derive the master key
        self.assertIsNotNone(master_key)
        self.assertIsNotNone(master_key.secret_exponent())
        
        # Verify we can get the BIP32 representation
        tprv = master_key.hwif(as_private=True)
        tpub = master_key.hwif(as_private=False)
        
        # tSTAK uses custom BIP32 prefixes (46002a10/a2aec9a6)
        self.assertIsNotNone(tprv)
        self.assertIsNotNone(tpub)
        
        # Verify we can derive child keys
        child_key = master_key.subkey(0)
        self.assertIsNotNone(child_key)
        self.assertNotEqual(child_key.secret_exponent(), master_key.secret_exponent())

    def test_stak_bip32_path_derivation(self):
        """Test BIP32 path derivation for STAK mainnet."""
        # Create a master key from a known seed
        master_key = stak_network.keys.bip32_seed(b"STRAKS BIP32 test")
        
        # Test standard BIP44 path derivation: m/44'/0'/0'/0/0
        # Note: STRAKS doesn't have a registered coin type, so we use a test path
        path = "0H/0/0"  # Simplified path for testing
        derived_key = master_key.subkey_for_path(path)
        
        self.assertIsNotNone(derived_key)
        self.assertIsNotNone(derived_key.address())
        
        # Verify the address starts with 'S' for STAK mainnet
        address = derived_key.address()
        self.assertTrue(address.startswith('S'))

    def test_tstak_bip32_path_derivation(self):
        """Test BIP32 path derivation for tSTAK testnet."""
        # Create a master key from a known seed
        master_key = tstak_network.keys.bip32_seed(b"STRAKS testnet BIP32 test")
        
        # Test standard path derivation
        path = "0H/0/0"
        derived_key = master_key.subkey_for_path(path)
        
        self.assertIsNotNone(derived_key)
        self.assertIsNotNone(derived_key.address())
        
        # Verify the address starts with 't' for tSTAK testnet
        address = derived_key.address()
        self.assertTrue(address.startswith('t'))

    def test_stak_address_generation(self):
        """Test that STAK addresses are generated correctly."""
        # Use a known secret exponent
        key = stak_network.keys.private(secret_exponent=1)
        address = key.address()
        
        # STAK mainnet addresses should start with 'S' (address prefix 0x3f)
        self.assertTrue(address.startswith('S'))
        
        # Verify consistent address generation
        key2 = stak_network.keys.private(secret_exponent=1)
        self.assertEqual(key.address(), key2.address())

    def test_tstak_address_generation(self):
        """Test that tSTAK addresses are generated correctly."""
        # Use a known secret exponent
        key = tstak_network.keys.private(secret_exponent=1)
        address = key.address()
        
        # tSTAK testnet addresses should start with 't' (address prefix 0x7f)
        self.assertTrue(address.startswith('t'))
        
        # Verify consistent address generation
        key2 = tstak_network.keys.private(secret_exponent=1)
        self.assertEqual(key.address(), key2.address())


if __name__ == '__main__':
    unittest.main()
