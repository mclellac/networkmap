import unittest
import json
import os
from unittest.mock import patch, MagicMock

from gi.repository import Gio

# Adjust the import path according to your project structure
# This assumes that your tests directory is at the same level as the src directory
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from profile_manager import (
    ProfileManager,
    ScanProfile,
    PROFILES_SCHEMA_KEY,
    ProfileNotFoundError,
    ProfileExistsError,
    ProfileStorageError,
)

# Define a dummy schema for testing purposes
TEST_SCHEMA_ID = "com.github.mclellac.NetworkMap.test"

class TestProfileManager(unittest.TestCase):

    def setUp(self):
        # Mock Gio.Settings
        self.mock_settings = MagicMock(spec=Gio.Settings)
        
        # Store original Gio.Settings to restore it later
        self.original_gio_settings = Gio.Settings

        # Patch Gio.Settings to return our mock
        self.gio_settings_patcher = patch('gi.repository.Gio.Settings', new=self.mock_settings_constructor)
        self.mock_gio_settings_class = self.gio_settings_patcher.start()

        self.profile_manager = ProfileManager(settings_schema_id=TEST_SCHEMA_ID)
        self.initial_profiles_json = [] # Start with no profiles
        self.mock_settings.get_strv.return_value = self.initial_profiles_json
        self.mock_settings.set_strv = MagicMock()

    def mock_settings_constructor(self, schema_id):
        if schema_id == TEST_SCHEMA_ID:
            return self.mock_settings
        # For any other schema, you might want to return a new MagicMock or raise an error
        return MagicMock(spec=Gio.Settings)


    def tearDown(self):
        # Stop the patcher to restore original Gio.Settings
        self.gio_settings_patcher.stop()
        Gio.Settings = self.original_gio_settings


    def _get_profile_list_from_set_strv_call(self):
        """Helper to extract profiles from the mock_settings.set_strv calls."""
        if not self.mock_settings.set_strv.called:
            return []
        # Get the arguments of the last call to set_strv
        args, _ = self.mock_settings.set_strv.call_args
        # args[0] should be PROFILES_SCHEMA_KEY, args[1] is the list of JSON strings
        json_strings = args[1]
        return [json.loads(s) for s in json_strings]

    def test_load_profiles_empty(self):
        self.mock_settings.get_strv.return_value = []
        profiles = self.profile_manager.load_profiles()
        self.assertEqual(profiles, [])

    def test_load_profiles_valid_data(self):
        profile1_data = {"name": "Test1", "os_fingerprint": True, "stealth_scan": False, "no_ping": True, "ports": "80", "nse_script": "http-title", "timing_template": "-T4", "additional_args": "-v"}
        self.mock_settings.get_strv.return_value = [json.dumps(profile1_data)]
        profiles = self.profile_manager.load_profiles()
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]['name'], "Test1")
        self.assertTrue(profiles[0]['os_fingerprint'])

    def test_load_profiles_malformed_json(self):
        self.mock_settings.get_strv.return_value = ["not a valid json"]
        # Expect ProfileStorageError or for it to be handled by printing to stderr and returning empty list
        # Based on current implementation, it prints to stderr and continues.
        # Let's check if it prints and returns an empty list or skips the entry.
        with patch('sys.stderr', new_callable=unittest.mock.StringIO) as mock_stderr:
            profiles = self.profile_manager.load_profiles()
            self.assertEqual(profiles, []) # Should skip the malformed entry
            self.assertIn("Error decoding profile JSON", mock_stderr.getvalue())


    def test_load_profiles_missing_name(self):
        profile_data = {"os_fingerprint": True} # Missing 'name'
        self.mock_settings.get_strv.return_value = [json.dumps(profile_data)]
        with patch('sys.stderr', new_callable=unittest.mock.StringIO) as mock_stderr:
            profiles = self.profile_manager.load_profiles()
            self.assertEqual(profiles, []) # Skips entry missing 'name'
            self.assertIn("Missing 'name' or not a dictionary", mock_stderr.getvalue())


    def test_save_profiles(self):
        profile1: ScanProfile = {"name": "SaveTest1", "os_fingerprint": False, "stealth_scan": True, "no_ping": False, "ports": "1-100", "nse_script": "", "timing_template": "-T3", "additional_args": ""}
        profiles_to_save = [profile1]
        self.profile_manager.save_profiles(profiles_to_save)
        self.mock_settings.set_strv.assert_called_once()
        # Check that the correct key was used
        self.assertEqual(self.mock_settings.set_strv.call_args[0][0], PROFILES_SCHEMA_KEY)
        # Check that the data was correctly serialized
        saved_json_list = self.mock_settings.set_strv.call_args[0][1]
        self.assertEqual(len(saved_json_list), 1)
        self.assertEqual(json.loads(saved_json_list[0]), profile1)

    def test_add_profile(self):
        new_profile: ScanProfile = {"name": "NewProfile", "os_fingerprint": True, "stealth_scan": True, "no_ping": False, "ports": "22,80", "nse_script": "ssh-hostkey", "timing_template": "", "additional_args": "-Pn"}
        self.profile_manager.add_profile(new_profile)
        
        saved_profiles = self._get_profile_list_from_set_strv_call()
        self.assertEqual(len(saved_profiles), 1)
        self.assertEqual(saved_profiles[0]['name'], "NewProfile")

    def test_add_profile_exists(self):
        profile1_data = {"name": "ExistingProfile", "os_fingerprint": True, "stealth_scan": False, "no_ping": True, "ports": "80", "nse_script": "http-title", "timing_template": "-T4", "additional_args": "-v"}
        self.mock_settings.get_strv.return_value = [json.dumps(profile1_data)]
        
        new_profile_same_name: ScanProfile = {"name": "ExistingProfile", "os_fingerprint": False, "stealth_scan": False, "no_ping": False, "ports": "", "nse_script": "", "timing_template": "", "additional_args": ""}
        with self.assertRaises(ProfileExistsError):
            self.profile_manager.add_profile(new_profile_same_name)

    def test_update_profile(self):
        profile1_data = {"name": "UpdateMe", "os_fingerprint": True, "stealth_scan": False, "no_ping": True, "ports": "80", "nse_script": "http-title", "timing_template": "-T4", "additional_args": "-v"}
        self.mock_settings.get_strv.return_value = [json.dumps(profile1_data)]

        updated_data: ScanProfile = {"name": "UpdatedName", "os_fingerprint": False, "stealth_scan": True, "no_ping": False, "ports": "443", "nse_script": "ssl-cert", "timing_template": "-T2", "additional_args": "-A"}
        self.profile_manager.update_profile("UpdateMe", updated_data)
        
        saved_profiles = self._get_profile_list_from_set_strv_call()
        self.assertEqual(len(saved_profiles), 1)
        self.assertEqual(saved_profiles[0]['name'], "UpdatedName")
        self.assertFalse(saved_profiles[0]['os_fingerprint'])

    def test_update_profile_not_found(self):
        self.mock_settings.get_strv.return_value = []
        updated_data: ScanProfile = {"name": "NonExistent", "os_fingerprint": False, "stealth_scan": False, "no_ping": False, "ports": "", "nse_script": "", "timing_template": "", "additional_args": ""}
        with self.assertRaises(ProfileNotFoundError):
            self.profile_manager.update_profile("NonExistent", updated_data)

    def test_update_profile_name_conflict(self):
        profile1 = {"name": "Profile1", "os_fingerprint": False, "stealth_scan": False, "no_ping": False, "ports": "", "nse_script": "", "timing_template": "", "additional_args": ""}
        profile2 = {"name": "Profile2", "os_fingerprint": False, "stealth_scan": False, "no_ping": False, "ports": "", "nse_script": "", "timing_template": "", "additional_args": ""}
        self.mock_settings.get_strv.return_value = [json.dumps(profile1), json.dumps(profile2)]
        
        updated_data_for_profile1: ScanProfile = {"name": "Profile2", "os_fingerprint": True, "stealth_scan": True, "no_ping": True, "ports": "123", "nse_script": "test", "timing_template": "-T0", "additional_args": "-sV"}
        with self.assertRaises(ProfileExistsError):
            self.profile_manager.update_profile("Profile1", updated_data_for_profile1)


    def test_delete_profile(self):
        profile1_data = {"name": "ToDelete", "os_fingerprint": True, "stealth_scan": False, "no_ping": True, "ports": "80", "nse_script": "http-title", "timing_template": "-T4", "additional_args": "-v"}
        profile2_data = {"name": "ToKeep", "os_fingerprint": False, "stealth_scan": True, "no_ping": True, "ports": "443", "nse_script": "", "timing_template": "-T1", "additional_args": ""}
        self.mock_settings.get_strv.return_value = [json.dumps(profile1_data), json.dumps(profile2_data)]

        self.profile_manager.delete_profile("ToDelete")
        saved_profiles = self._get_profile_list_from_set_strv_call()
        self.assertEqual(len(saved_profiles), 1)
        self.assertEqual(saved_profiles[0]['name'], "ToKeep")

    def test_delete_profile_not_found(self):
        self.mock_settings.get_strv.return_value = []
        with self.assertRaises(ProfileNotFoundError):
            self.profile_manager.delete_profile("NonExistent")

    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_export_profiles_to_file(self, mock_file_open):
        profiles_data: List[ScanProfile] = [
            {"name": "Export1", "os_fingerprint": True, "ports": "80", "stealth_scan":False, "no_ping":False, "nse_script":"", "timing_template":"", "additional_args":""},
            {"name": "Export2", "os_fingerprint": False, "ports": "443", "stealth_scan":True, "no_ping":True, "nse_script":"http-title", "timing_template":"-T4", "additional_args":"-A"}
        ]
        self.mock_settings.get_strv.return_value = [json.dumps(p) for p in profiles_data]
        
        test_filepath = "/fake/path/profiles.json"
        self.profile_manager.export_profiles_to_file(test_filepath)

        mock_file_open.assert_called_once_with(test_filepath, 'w', encoding='utf-8')
        # Check what was written to the file
        # mock_file_open().write.call_args[0][0] will give you the string written
        written_content = mock_file_open().write.call_args[0][0]
        self.assertEqual(json.loads(written_content), profiles_data)

    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_export_profiles_file_error(self, mock_file_open):
        self.mock_settings.get_strv.return_value = [] # No profiles, but error is from file writing
        mock_file_open.side_effect = OSError("Failed to write")
        
        with self.assertRaises(ProfileStorageError):
            self.profile_manager.export_profiles_to_file("/fake/path/profiles.json")

    def test_import_profiles_from_file(self):
        profiles_to_import_json = json.dumps([
            {"name": "Import1", "os_fingerprint": True, "ports": "22", "stealth_scan":False, "no_ping":False, "nse_script":"", "timing_template":"", "additional_args":""},
            {"name": "Import2", "os_fingerprint": False, "ports": "8080", "stealth_scan":True, "no_ping":True, "nse_script":"banner", "timing_template":"-T5", "additional_args":"-sV"}
        ])
        
        # Initially no profiles in GSettings
        self.mock_settings.get_strv.return_value = []
        
        mock_file = unittest.mock.mock_open(read_data=profiles_to_import_json)
        with patch('builtins.open', mock_file):
            imported, skipped = self.profile_manager.import_profiles_from_file("/fake/import.json")
        
        self.assertEqual(imported, 2)
        self.assertEqual(skipped, 0)
        
        saved_profiles = self._get_profile_list_from_set_strv_call()
        self.assertEqual(len(saved_profiles), 2)
        self.assertEqual(saved_profiles[0]['name'], "Import1")
        self.assertEqual(saved_profiles[1]['name'], "Import2")


    def test_import_profiles_skip_duplicates_and_malformed(self):
        existing_profile = {"name": "Existing", "os_fingerprint": True, "ports": "80", "stealth_scan":False, "no_ping":False, "nse_script":"", "timing_template":"", "additional_args":""}
        self.mock_settings.get_strv.return_value = [json.dumps(existing_profile)] # One profile already exists

        profiles_to_import_json = json.dumps([
            {"name": "NewImport", "os_fingerprint": True, "ports": "22", "stealth_scan":False, "no_ping":False, "nse_script":"", "timing_template":"", "additional_args":""},
            {"name": "Existing", "os_fingerprint": False, "ports": "8080", "stealth_scan":True, "no_ping":True, "nse_script":"banner", "timing_template":"-T5", "additional_args":"-sV"}, # Duplicate
            {"ports": "123"}, # Malformed, missing name
            {"name": "AnotherNew", "os_fingerprint": False, "ports": "443", "stealth_scan":False, "no_ping":False, "nse_script":"", "timing_template":"", "additional_args":""}
        ])
        
        mock_file = unittest.mock.mock_open(read_data=profiles_to_import_json)
        with patch('builtins.open', mock_file), \
             patch('sys.stderr', new_callable=unittest.mock.StringIO) as mock_stderr:
            imported, skipped = self.profile_manager.import_profiles_from_file("/fake/import_mixed.json")
        
        self.assertEqual(imported, 2) # NewImport, AnotherNew
        self.assertEqual(skipped, 2) # Existing, Malformed
        
        # Check stderr for warnings about skipped profiles
        stderr_output = mock_stderr.getvalue()
        self.assertIn("Skipping profile 'Existing' from import", stderr_output)
        self.assertIn("missing, invalid, or empty 'name'", stderr_output) # For the malformed one

        saved_profiles = self._get_profile_list_from_set_strv_call()
        self.assertEqual(len(saved_profiles), 3) # Existing + NewImport + AnotherNew
        saved_names = {p['name'] for p in saved_profiles}
        self.assertIn("Existing", saved_names)
        self.assertIn("NewImport", saved_names)
        self.assertIn("AnotherNew", saved_names)

    @patch('builtins.open', side_effect=FileNotFoundError("File not found for import"))
    def test_import_profiles_file_not_found(self, mock_open):
        with self.assertRaises(ProfileStorageError) as context:
            self.profile_manager.import_profiles_from_file("/non/existent/file.json")
        self.assertIn("Import file not found", str(context.exception))

    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data="Invalid JSON data {")
    def test_import_profiles_invalid_json_structure(self, mock_open):
        with self.assertRaises(ProfileStorageError) as context:
            self.profile_manager.import_profiles_from_file("/fake/invalid_json.json")
        self.assertIn("Invalid JSON structure in file", str(context.exception))

    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data='{"not_a_list": "is_a_dict"}')
    def test_import_profiles_not_a_list(self, mock_open):
        with self.assertRaises(ProfileStorageError) as context:
            self.profile_manager.import_profiles_from_file("/fake/not_a_list.json")
        self.assertIn("Expected a JSON list of profiles", str(context.exception))


if __name__ == '__main__':
    unittest.main()
