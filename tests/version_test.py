import unittest
import pycoin


class VersionTest(unittest.TestCase):
    def test_version_is_defined(self):
        """Test that __version__ attribute is defined."""
        self.assertTrue(hasattr(pycoin, '__version__'))
        self.assertIsNotNone(pycoin.__version__)
        
    def test_version_is_string(self):
        """Test that __version__ is a string."""
        self.assertIsInstance(pycoin.__version__, str)
        
    def test_version_not_empty(self):
        """Test that __version__ is not empty."""
        self.assertNotEqual(pycoin.__version__, "")
        
    def test_version_value(self):
        """Test that __version__ has a reasonable value."""
        # Version should be either a valid version string or "unknown"
        # Valid version strings contain digits (e.g., "0.1.0", "1.2.3", "0.1.dev2")
        self.assertTrue(
            pycoin.__version__ == "unknown" or 
            any(char.isdigit() for char in pycoin.__version__)
        )


if __name__ == "__main__":
    unittest.main()
