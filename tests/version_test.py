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
        # Version should be either a version string or "unknown"
        self.assertTrue(
            pycoin.__version__ == "unknown" or 
            len(pycoin.__version__) > 0
        )


if __name__ == "__main__":
    unittest.main()
