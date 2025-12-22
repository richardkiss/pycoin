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
        """Test that __version__ has a valid version format."""
        # Version should be either "unknown" or start with a digit (semantic version)
        # setuptools_scm can generate formats like: "1.0.0", "0.1.dev2", "1.0+dirty", 
        # "1.0.dev2+gabcd1234", so we use a permissive check
        if pycoin.__version__ != "unknown":
            # Valid versions should be non-empty and start with a digit
            self.assertGreater(
                len(pycoin.__version__), 0,
                "Version should not be empty"
            )
            self.assertTrue(
                pycoin.__version__[0].isdigit(),
                f"Version should start with a digit, got: {pycoin.__version__}"
            )


if __name__ == "__main__":
    unittest.main()
