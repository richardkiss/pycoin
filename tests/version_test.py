import unittest
import re
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
        """Test that __version__ has a valid version format."""
        # Version should be either "unknown" or match a semantic version pattern
        # Valid formats: "1.0.0", "0.1.dev2", "2.3.4rc1", "1.0", etc.
        # Pattern allows: digits.digits(.more)(.optional_suffix_with_digits)
        version_pattern = r'^\d+(\.\d+)*(\.[a-zA-Z]+\d*)?$'
        self.assertTrue(
            pycoin.__version__ == "unknown" or 
            re.match(version_pattern, pycoin.__version__) is not None
        )


if __name__ == "__main__":
    unittest.main()
