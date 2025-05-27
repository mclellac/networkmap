import unittest
from unittest.mock import patch, MagicMock # Added MagicMock
import sys 
import os

# Adjust the path to import from the src directory
# This ensures that 'from utils import ...' works correctly
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

# Now, import from src.utils
# Note: The tool environment might handle path differently.
# If 'from utils import ...' fails, it might be 'from src.utils import ...'
# However, the original test structure implies 'utils' is directly importable after path modification.
from src.utils import is_macos, is_linux, is_flatpak, is_root, discover_nse_scripts, apply_theme
from gi.repository import Adw # Needed for apply_theme test

class TestPlatformUtils(unittest.TestCase):

    @patch('src.utils.sys.platform')
    def test_is_macos(self, mock_sys_platform):
        # Test when platform is macOS
        mock_sys_platform.return_value = "darwin"
        self.assertTrue(is_macos())

        # Test when platform is not macOS (e.g., Linux)
        mock_sys_platform.return_value = "linux"
        self.assertFalse(is_macos())

        # Test when platform is not macOS (e.g., Windows)
        mock_sys_platform.return_value = "win32"
        self.assertFalse(is_macos())

    @patch('src.utils.sys.platform')
    def test_is_linux(self, mock_sys_platform):
        # Test when platform is Linux
        mock_sys_platform.return_value = "linux"
        self.assertTrue(is_linux())

        # Test with a variation like "linux2"
        mock_sys_platform.return_value = "linux2"
        self.assertTrue(is_linux())
        
        # Test when platform is not Linux (e.g., macOS)
        mock_sys_platform.return_value = "darwin"
        self.assertFalse(is_linux())

        # Test when platform is not Linux (e.g., Windows)
        mock_sys_platform.return_value = "win32"
        self.assertFalse(is_linux())

    @patch('src.utils.os.environ.get')
    @patch('src.utils.os.path.exists')
    def test_is_flatpak(self, mock_os_path_exists, mock_os_environ_get):
        # Scenario 1: /.flatpak-info exists
        mock_os_path_exists.return_value = True
        # os.environ.get should not be called due to short-circuiting.
        # So, we don't need to set its return_value for this specific path.
        self.assertTrue(is_flatpak())
        mock_os_path_exists.assert_called_once_with('/.flatpak-info')
        mock_os_environ_get.assert_not_called() # Important check for short-circuit

        # Reset mocks for next scenario
        mock_os_path_exists.reset_mock()
        mock_os_environ_get.reset_mock()

        # Scenario 2: FLATPAK_ID environment variable is set
        mock_os_path_exists.return_value = False # /.flatpak-info does not exist
        mock_os_environ_get.return_value = "com.github.mclellac.NetworkMap" # FLATPAK_ID is set
        self.assertTrue(is_flatpak())
        mock_os_path_exists.assert_called_once_with('/.flatpak-info')
        mock_os_environ_get.assert_called_once_with('FLATPAK_ID')
        
        # Reset mocks for next scenario
        mock_os_path_exists.reset_mock()
        mock_os_environ_get.reset_mock()

        # Scenario 3: Neither Flatpak indicator is present
        mock_os_path_exists.return_value = False # /.flatpak-info does not exist
        mock_os_environ_get.return_value = None  # FLATPAK_ID is not set
        self.assertFalse(is_flatpak())
        mock_os_path_exists.assert_called_once_with('/.flatpak-info')
        mock_os_environ_get.assert_called_once_with('FLATPAK_ID')

    @patch('src.utils.os.geteuid')
    def test_is_root(self, mock_geteuid):
        # Test when user is root
        mock_geteuid.return_value = 0
        self.assertTrue(is_root())

        # Test when user is not root
        mock_geteuid.return_value = 1000
        self.assertFalse(is_root())

class TestOtherUtils(unittest.TestCase):
    @patch('src.utils.Adw.StyleManager.get_default') # Patch the static/class method
    def test_apply_theme(self, mock_get_default_style_manager):
        # This mock will be the return value of Adw.StyleManager.get_default()
        mock_style_manager_instance = MagicMock()
        mock_get_default_style_manager.return_value = mock_style_manager_instance
        
        apply_theme("light")
        mock_style_manager_instance.set_color_scheme.assert_called_with(Adw.ColorScheme.FORCE_LIGHT)
        
        apply_theme("dark")
        mock_style_manager_instance.set_color_scheme.assert_called_with(Adw.ColorScheme.FORCE_DARK)

        apply_theme("system")
        mock_style_manager_instance.set_color_scheme.assert_called_with(Adw.ColorScheme.DEFAULT)

        apply_theme("invalid_theme_name") # Test default case
        mock_style_manager_instance.set_color_scheme.assert_called_with(Adw.ColorScheme.DEFAULT)


    @patch('src.utils.os.listdir')
    @patch('src.utils.os.path.isdir', return_value=True)
    @patch('src.utils.os.access', return_value=True)
    @patch('src.utils.os.path.isfile', return_value=True)
    def test_discover_nse_scripts_normal_case(self, mock_isfile, mock_access, mock_isdir, mock_listdir):
        mock_listdir.return_value = ["http-title.nse", "smb-os-discovery.nse", "ssh-hostkey.nse", "nonscript.txt", "banner.nse"]
        
        scripts = discover_nse_scripts()
        
        self.assertIn("http-title", scripts)
        self.assertIn("smb-os-discovery", scripts)
        self.assertIn("ssh-hostkey", scripts)
        self.assertIn("banner", scripts) # 'banner' is categorized as 'zzz_other'
        self.assertNotIn("nonscript.txt", scripts)
        
        # Check relative order based on current SCRIPT_PREFIXES and 'zzz_other' for banner
        # http, smb, ssh are categories. 'banner' is 'zzz_other'.
        # Expected order: http-title, smb-os-discovery, ssh-hostkey, banner (because 'b' in banner < 'h' in http if not for prefixes)
        # With prefixes, it should be:
        # http-title (http category)
        # smb-os-discovery (smb category)
        # ssh-hostkey (ssh category)
        # banner (zzz_other category)
        # The SCRIPT_PREFIXES list determines category order before 'zzz_other'.
        # 'http' is before 'smb', which is before 'ssh'. 'zzz_other' is last.
        expected_order_segment = ["http-title", "smb-os-discovery", "ssh-hostkey", "banner"]
        
        # Create a list of found scripts in the expected order segment
        found_order_segment = [s for s in scripts if s in expected_order_segment]
        
        self.assertEqual(found_order_segment, expected_order_segment, 
                         f"Script order issue. Got: {scripts}")


    @patch('src.utils.os.path.isdir', return_value=False) # Simulate script path not found
    def test_discover_nse_scripts_no_dir(self, mock_isdir):
        scripts = discover_nse_scripts()
        self.assertEqual(scripts, [])

    @patch('src.utils.os.listdir', side_effect=OSError("Permission denied"))
    @patch('src.utils.os.path.isdir', return_value=True)
    @patch('src.utils.os.access', return_value=True)
    def test_discover_nse_scripts_os_error(self, mock_access, mock_isdir, mock_listdir):
        scripts = discover_nse_scripts()
        self.assertEqual(scripts, [])

if __name__ == '__main__':
    unittest.main()
