import unittest
from unittest.mock import patch
import sys
import os

# Adjust sys.path to allow importing from the 'src' directory
# This is often necessary when running tests from the 'tests' directory
# and the modules to be tested are in a sibling directory like 'src'.
# The exact path adjustment might depend on the project structure and how tests are run.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.utils import is_root

class TestIsRoot(unittest.TestCase):
    """
    Test suite for the is_root() utility function.
    """

    @patch('os.geteuid')
    def test_is_root_functionality(self, mock_geteuid):
        """
        Tests the is_root() function with mocked os.geteuid().
        """
        # Test case 1: Effective UID is 0 (root)
        mock_geteuid.return_value = 0
        self.assertTrue(is_root(), "is_root() should return True when euid is 0")

        # Test case 2: Effective UID is non-zero (not root)
        mock_geteuid.return_value = 1000
        self.assertFalse(is_root(), "is_root() should return False when euid is not 0")

        # Test case 3: Effective UID is another non-zero value
        mock_geteuid.return_value = -1 # Though typically positive, test with another non-zero
        self.assertFalse(is_root(), "is_root() should return False when euid is not 0")

if __name__ == '__main__':
    unittest.main()
