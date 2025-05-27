import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import sys
import logging

# Adjust import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from utils import apply_theme, discover_nse_scripts, is_root, is_macos, is_linux, is_flatpak

# Mock Adw for apply_theme if not available in test environment
try:
    from gi.repository import Adw
except ImportError:
    MockAdw = MagicMock()
    MockAdw.StyleManager = MagicMock()
    MockAdw.StyleManager.get_default = MagicMock(return_value=MagicMock())
    # Define Adw.ColorScheme as an object that can have attributes set
    MockColorScheme = MagicMock()
    MockColorScheme.FORCE_LIGHT = 0 # Dummy values, actual values don't matter for mocking logic
    MockColorScheme.FORCE_DARK = 1
    MockColorScheme.DEFAULT = 2
    MockAdw.ColorScheme = MockColorScheme
    
    sys.modules['gi.repository.Adw'] = MockAdw
    Adw = MockAdw # Make the mock available in the global scope for the tests


class TestUtils(unittest.TestCase):

    # --- Tests for apply_theme ---
    @patch('utils.Adw.StyleManager.get_default')
    def test_apply_theme_light(self, mock_get_style_manager):
        mock_manager_instance = MagicMock()
        mock_get_style_manager.return_value = mock_manager_instance
        apply_theme("light")
        mock_manager_instance.set_color_scheme.assert_called_once_with(Adw.ColorScheme.FORCE_LIGHT)

    @patch('utils.Adw.StyleManager.get_default')
    def test_apply_theme_dark(self, mock_get_style_manager):
        mock_manager_instance = MagicMock()
        mock_get_style_manager.return_value = mock_manager_instance
        apply_theme("dark")
        mock_manager_instance.set_color_scheme.assert_called_once_with(Adw.ColorScheme.FORCE_DARK)

    @patch('utils.Adw.StyleManager.get_default')
    def test_apply_theme_system(self, mock_get_style_manager):
        mock_manager_instance = MagicMock()
        mock_get_style_manager.return_value = mock_manager_instance
        apply_theme("system")
        mock_manager_instance.set_color_scheme.assert_called_once_with(Adw.ColorScheme.DEFAULT)

    @patch('utils.Adw.StyleManager.get_default')
    def test_apply_theme_invalid(self, mock_get_style_manager):
        mock_manager_instance = MagicMock()
        mock_get_style_manager.return_value = mock_manager_instance
        apply_theme("invalid_theme_name") # Should default to system
        mock_manager_instance.set_color_scheme.assert_called_once_with(Adw.ColorScheme.DEFAULT)

    # --- Tests for discover_nse_scripts ---
    # Patch os.path.isdir, os.access, os.listdir, os.path.isfile which are used by discover_nse_scripts
    @patch('utils.os.path.isfile') # Patch where it's used
    @patch('utils.os.listdir')   # Patch where it's used
    @patch('utils.os.access')    # Patch where it's used
    @patch('utils.os.path.isdir') # Patch where it's used
    def test_discover_nse_scripts_success_and_categorization(self, mock_isdir, mock_access, mock_listdir, mock_isfile):
        # Simulate that the first potential path is valid
        mock_isdir.side_effect = lambda p: p == "/usr/share/nmap/scripts/" 
        mock_access.side_effect = lambda p, mode: p == "/usr/share/nmap/scripts/" and mode == os.R_OK

        mock_listdir.return_value = [
            "http-title.nse", "smb-os-discovery.nse", "ssh-hostkey.nse", 
            "mysql-empty-password.nse", "rdp-enum-encryption.nse", "ftp-anon.nse",
            "a-test-script.nse", "another.nse", "http-malware-check.nse", "auth-spoof.nse"
        ]
        # All listed items are files ending with .nse
        mock_isfile.return_value = True 

        scripts = discover_nse_scripts()
        
        expected_scripts_set = {
            "http-title", "smb-os-discovery", "ssh-hostkey", "mysql-empty-password",
            "rdp-enum-encryption", "ftp-anon", "a-test-script", "another",
            "http-malware-check", "auth-spoof"
        }
        self.assertEqual(set(scripts), expected_scripts_set, "Discovered scripts do not match expected set.")

        # Check categorization and sorting (example checks)
        # Based on SCRIPT_PREFIXES and then alphabetical for 'zzz_other'
        # 'auth' scripts should come early alphabetically among categories.
        # 'http' scripts next, then 'mysql', 'rdp', 'smb', 'ssh'.
        # 'zzz_other' (like 'a-test-script', 'another') should be last.
        
        # Example: auth-spoof should appear before http-title
        if "auth-spoof" in scripts and "http-title" in scripts:
            self.assertTrue(scripts.index("auth-spoof") < scripts.index("http-title"), "Auth scripts should sort before http.")

        # Example: http-title should appear before smb-os-discovery
        if "http-title" in scripts and "smb-os-discovery" in scripts:
             self.assertTrue(scripts.index("http-title") < scripts.index("smb-os-discovery"), "HTTP scripts should sort before SMB.")

        # Example: a-test-script (zzz_other) should be after categorized scripts like ssh-hostkey
        if "a-test-script" in scripts and "ssh-hostkey" in scripts:
            self.assertTrue(scripts.index("ssh-hostkey") < scripts.index("a-test-script"), "Categorized scripts should sort before 'other'.")
        
        # Check if 'another' (also zzz_other) is sorted correctly relative to 'a-test-script'
        if "a-test-script" in scripts and "another" in scripts:
            self.assertTrue(scripts.index("a-test-script") < scripts.index("another"), "'a-test-script' should sort before 'another'.")


    @patch('utils.os.path.isdir', return_value=False) # All potential paths are not dirs
    @patch('logging.warning') 
    def test_discover_nse_scripts_no_valid_directory(self, mock_log_warning, mock_isdir):
        scripts = discover_nse_scripts()
        self.assertEqual(scripts, [])
        mock_log_warning.assert_called_once()
        self.assertIn("No accessible Nmap NSE script directory found", mock_log_warning.call_args[0][0])

    @patch('utils.os.path.isdir', return_value=True)
    @patch('utils.os.access', return_value=True)
    @patch('utils.os.listdir', side_effect=OSError("Permission denied to list directory"))
    @patch('logging.error')
    def test_discover_nse_scripts_os_error_on_listdir(self, mock_log_error, mock_listdir, mock_access, mock_isdir):
        # Ensure isdir and access pass for at least one path
        mock_isdir.side_effect = lambda p: p == "/usr/share/nmap/scripts/"
        mock_access.side_effect = lambda p, mode: p == "/usr/share/nmap/scripts/" and mode == os.R_OK
        
        scripts = discover_nse_scripts()
        self.assertEqual(scripts, [])
        mock_log_error.assert_called_once()
        self.assertIn("Error reading NSE script directory", mock_log_error.call_args[0][0])

    @patch('utils.os.path.isdir', return_value=True)
    @patch('utils.os.access', return_value=True)
    @patch('utils.os.listdir', return_value=["script.txt", "not_an_nse.sh", "only_nse.nse"])
    @patch('utils.os.path.isfile', side_effect=lambda p: p.endswith(".nse")) # Only only_nse.nse is a file
    @patch('logging.info') # Check for info log if directory is empty of .nse files
    def test_discover_nse_scripts_only_one_nse_file(self, mock_log_info, mock_isfile, mock_listdir, mock_access, mock_isdir):
        mock_isdir.side_effect = lambda p: p == "/usr/share/nmap/scripts/"
        mock_access.side_effect = lambda p, mode: p == "/usr/share/nmap/scripts/" and mode == os.R_OK

        scripts = discover_nse_scripts()
        self.assertEqual(scripts, ["only_nse"]) # Expecting 'only_nse' categorized as 'zzz_other'

    @patch('utils.os.path.isdir', return_value=True)
    @patch('utils.os.access', return_value=True)
    @patch('utils.os.listdir', return_value=[]) # Empty directory
    @patch('logging.info')
    def test_discover_nse_scripts_empty_directory(self, mock_log_info, mock_listdir, mock_access, mock_isdir):
        mock_isdir.side_effect = lambda p: p == "/usr/share/nmap/scripts/"
        mock_access.side_effect = lambda p, mode: p == "/usr/share/nmap/scripts/" and mode == os.R_OK
        
        scripts = discover_nse_scripts()
        self.assertEqual(scripts, [])
        mock_log_info.assert_called_once()
        self.assertIn("No NSE scripts found in", mock_log_info.call_args[0][0])

    # --- Tests for platform detection functions ---
    @patch('utils.os.geteuid', return_value=0) # Patch where it's used
    def test_is_root_true(self, mock_geteuid):
        self.assertTrue(is_root())

    @patch('utils.os.geteuid', return_value=1000) # Patch where it's used
    def test_is_root_false(self, mock_geteuid):
        self.assertFalse(is_root())

    @patch('sys.platform', "darwin")
    def test_is_macos_true(self): # No need to mock sys.platform if it's directly used from sys
        self.assertTrue(is_macos())

    @patch('sys.platform', "linux")
    def test_is_macos_false(self):
        self.assertFalse(is_macos())

    @patch('sys.platform', "linux2") 
    def test_is_linux_true(self):
        self.assertTrue(is_linux())
        
    @patch('sys.platform', "win32")
    def test_is_linux_false(self):
        self.assertFalse(is_linux())

    @patch('utils.os.path.exists', return_value=True) # Patch where it's used
    def test_is_flatpak_true_by_file(self, mock_exists):
        with patch.dict(os.environ, {}, clear=True): 
             self.assertTrue(is_flatpak())
        mock_exists.assert_called_with('/.flatpak-info')

    @patch('utils.os.path.exists', return_value=False) # Patch where it's used
    @patch.dict(os.environ, {'FLATPAK_ID': 'com.example.App'}, clear=True)
    def test_is_flatpak_true_by_env_var(self, mock_exists):
        self.assertTrue(is_flatpak())

    @patch('utils.os.path.exists', return_value=False) # Patch where it's used
    @patch.dict(os.environ, {}, clear=True) 
    def test_is_flatpak_false(self, mock_exists):
        self.assertFalse(is_flatpak())


if __name__ == '__main__':
    unittest.main()
