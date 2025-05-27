import unittest
from unittest.mock import MagicMock, PropertyMock, patch
import sys
import os

# Adjust the path to import NmapScanner from the src directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from nmap_scanner import NmapScanner
# We need PortScannerError for one of the tests
try:
    # For mocking nmap[host] behavior and PortScannerError
    from nmap import PortScannerError, PortScannerHostDict
except ImportError:
    # Define dummy classes if python-nmap is not installed,
    # tests relying on its actual presence might be skipped or adapted.
    class PortScannerError(Exception): # type: ignore
        pass
    class PortScannerHostDict(dict): # type: ignore # Simple mock for the type
        def hostname(self): return self.get('hostname', "")
        def state(self): return self.get('state', {}).get('state', "") # type: ignore
        def all_protocols(self): return list(self.get('protocols', {}).keys()) # type: ignore
        # Add .get() to mimic dict behavior for protocol access like host_scan_data.get(proto, {})
        def get(self, key, default=None): # type: ignore
            if key in self: # Check if key exists directly (e.g. 'tcp', 'udp', 'osmatch')
                return self[key]
            # Fallback for other attributes that might be accessed via .get()
            # For example, if the internal structure of PortScannerHostDict uses .get for its own methods
            return super().get(key, default)


from nmap_scanner import NmapArgumentError, NmapScanParseError # Import custom exceptions

# Mock Gio before NmapScanner is imported if NmapScanner uses Gio at module level
# However, Gio is used within methods, so patching at test method/class level is fine.
# For simplicity, we'll patch it where needed.

class TestNmapScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = NmapScanner()
        # Mock the nmap.PortScanner instance (self.nm)
        # self.scanner.nm is an instance of nmap.PortScanner
        # We need to mock the scan method on this instance for some tests
        self.scanner.nm = MagicMock()
        # If NmapScanner() itself instantiated Gio.Settings at __init__, we'd mock it here.
        # But it's done within methods like scan() and build_scan_args().

    def _mock_gsettings_get_string(self, settings_dict):
        """
        Helper to create a side_effect function for Gio.Settings.get_string.
        `settings_dict` is a dictionary like {"dns-servers": "1.1.1.1", "default-nmap-arguments": "-T4"}.
        """
        def mock_get_string(key):
            return settings_dict.get(key, "") # Default to empty string if key not in mock
        return mock_get_string

    def test_parse_results_no_hosts_found(self):
        # Mock nmap.PortScanner().all_hosts() to return an empty list
        self.scanner.nm.all_hosts.return_value = []
        
        hosts_data, error_message = self.scanner._parse_scan_results(do_os_fingerprint=False)
        
        self.assertEqual(hosts_data, [])
        self.assertEqual(error_message, "No hosts found.")

    # Existing tests for _parse_scan_results seem okay and don't directly interact with GSettings.
    # We will leave them as is for now.

    def test_parse_results_single_host_no_os(self):
        mock_host_ip = '192.168.1.1'
        # This is what self.nm[mock_host_ip] would return (a PortScannerHostDict like object)
        mock_host_scan_data_dict = {
            'hostname': 'testhost.local', # Accessed by .hostname()
            'state': {'state': 'up', 'reason': 'arp-response'}, # Accessed by .state()
            'protocols': { # Used by .all_protocols()
                'tcp': { # Accessed by host_scan_data.get('tcp', {})
                    80: {'state': 'open', 'reason': 'syn-ack', 'name': 'http', 'product': 'Apache httpd', 'version': '2.4.29'},
                    443: {'state': 'closed', 'reason': 'reset', 'name': 'https', 'product': '', 'version': ''}
                }
            },
            # 'udp': {} # No UDP ports for simplicity in this test
        }

        self.scanner.nm.all_hosts.return_value = [mock_host_ip]
        
        # self.scanner.nm[mock_host_ip] should return an object that behaves like PortScannerHostDict
        mock_ps_host_dict_obj = PortScannerHostDict(mock_host_scan_data_dict)
        # If PortScannerHostDict needs more methods mocked, they should be added to its dummy definition or here.
        # For instance, if the parsing code directly called mock_ps_host_dict_obj['tcp'] instead of mock_ps_host_dict_obj.get('tcp', {})
        # then the PortScannerHostDict mock needs to support __getitem__ for 'tcp' etc.
        # The current NmapScanner._parse_scan_results uses host_scan_data.get(proto, {})
        
        self.scanner.nm.__getitem__.return_value = mock_ps_host_dict_obj
        
        hosts_data, error_message = self.scanner._parse_scan_results(do_os_fingerprint=False)
        
        self.assertIsNone(error_message)
        self.assertEqual(len(hosts_data), 1)
        
        host_result = hosts_data[0]
        self.assertEqual(host_result['id'], mock_host_ip)
        self.assertEqual(host_result['hostname'], 'testhost.local')
        self.assertEqual(host_result['state'], 'up')
        self.assertIsNone(host_result['os_fingerprint'])
        self.assertEqual(len(host_result['ports']), 2)
        
        http_port = next(p for p in host_result['ports'] if p['portid'] == 80)
        self.assertEqual(http_port['state'], 'open')
        self.assertEqual(http_port['service']['name'], 'http')
        
        https_port = next(p for p in host_result['ports'] if p['portid'] == 443)
        self.assertEqual(https_port['state'], 'closed')

        self.assertIn(f"Host: {mock_host_ip}", host_result['raw_details_text'])
        self.assertIn("Port: 80/tcp", host_result['raw_details_text'])
        self.assertNotIn("OS Fingerprint:", host_result['raw_details_text'])


    def test_parse_results_single_host_with_os_fingerprint(self):
        mock_host_ip = '192.168.1.2'
        mock_os_match_entry = { # This is an entry within the 'osmatch' list
            'name': 'Linux 4.15', 
            'accuracy': '100', # Note: accuracy is a string in python-nmap
            'osclass': [{
                'type': 'OS', 'vendor': 'Linux', 'osfamily': 'Linux', 
                'osgen': '4.X', 'accuracy': '100'
            }]
        }
        mock_host_scan_data_dict = {
            'hostname': 'linuxhost.local',
            'state': {'state': 'up'},
            'protocols': {
                'tcp': {
                    22: {'state': 'open', 'name': 'ssh'}
                }
            },
            'osmatch': [mock_os_match_entry] # OS match data
        }

        self.scanner.nm.all_hosts.return_value = [mock_host_ip]
        mock_ps_host_dict_obj = PortScannerHostDict(mock_host_scan_data_dict)
        self.scanner.nm.__getitem__.return_value = mock_ps_host_dict_obj
        
        hosts_data, error_message = self.scanner._parse_scan_results(do_os_fingerprint=True)
        
        self.assertIsNone(error_message)
        self.assertEqual(len(hosts_data), 1)
        host_result = hosts_data[0]
        
        self.assertIsNotNone(host_result['os_fingerprint'])
        self.assertEqual(host_result['os_fingerprint']['name'], 'Linux 4.15')
        self.assertEqual(host_result['os_fingerprint']['accuracy'], '100')

        self.assertIn("OS Fingerprint:", host_result['raw_details_text'])
        self.assertIn("Best Match: Linux 4.15 (Accuracy: 100%)", host_result['raw_details_text'])

    def test_scan_invalid_arguments_type(self):
        target_host = "localhost"
        # Pass integer 123 as additional_args_str, expecting NmapArgumentError
        # This test needs to be adapted because scan() now fetches GSettings.
        # We can mock GSettings to return empty defaults for this specific test.
        with patch('src.nmap_scanner.Gio.Settings') as mock_gio_settings_constructor:
            mock_settings_instance = MagicMock()
            mock_settings_instance.get_string.return_value = "" # No default args, no dns
            mock_gio_settings_constructor.return_value = mock_settings_instance
            
            target_host = "localhost"
            result_data, error_msg = self.scanner.scan(target_host, False, 123) # type: ignore
            
            self.assertIsNone(result_data)
            self.assertIsNotNone(error_msg)
            self.assertIn("Argument error: Additional arguments must be a string.", error_msg)

    @patch('src.nmap_scanner.Gio.Settings') # Mock GSettings for the scan method
    def test_scan_nmap_execution_error(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "default-nmap-arguments": "-sV", # Provide some default
            "dns-servers": ""
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance

        self.scanner.nm.scan.side_effect = PortScannerError("Test Nmap Execution Error")
        
        target_host = "localhost"
        # Note: `scan` no longer takes `default_args_str`. It's fetched from GSettings.
        result_data, error_msg = self.scanner.scan(target_host, False, "") # additional_args_str is empty
        
        self.assertIsNone(result_data)
        self.assertIsNotNone(error_msg)
        self.assertIn("Nmap execution error: Test Nmap Execution Error", error_msg)


    # --- Tests for build_scan_args ---
    # These tests will now need to mock Gio.Settings for "dns-servers"
    # and pass the equivalent of "default-nmap-arguments" via the default_args_str parameter.

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_os_fingerprint(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        # Simulate no custom DNS servers from GSettings for this test
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        # Simulate default_args_str coming from GSettings (e.g. containing -sV)
        args = self.scanner.build_scan_args(
            do_os_fingerprint=True, 
            additional_args_str="-T4",
            default_args_str="-sV --host-timeout=30s" # Explicitly pass defaults
        )
        args_list = args.split()
        self.assertIn("-O", args_list)
        self.assertIn("-sV", args_list)
        self.assertIn("--host-timeout=30s", args) # Check the full arg with value
        self.assertIn("-T4", args_list)
        self.assertNotIn("--dns-servers", args) # Ensure DNS not added if GSetting for it is empty

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_no_os_fingerprint(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        args = self.scanner.build_scan_args(
            do_os_fingerprint=False, 
            additional_args_str="--top-ports 10",
            default_args_str="-sV" # Simulate GSettings providing -sV
        )
        args_list = args.split()
        self.assertNotIn("-O", args_list)
        self.assertIn("-sV", args_list)
        self.assertIn("--top-ports", args_list)
        self.assertIn("10", args_list)

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_additional_args_sV_handling(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        # Case 1: User provides -sV in additional_args_str, GSettings default is empty for this part
        args_user_sV = self.scanner.build_scan_args(False, "-sV -p 80,443", default_args_str="")
        self.assertEqual(args_user_sV.count("-sV"), 1)
        self.assertIn("-p", args_user_sV.split())

        # Case 2: User provides -A, GSettings default is empty
        args_user_A = self.scanner.build_scan_args(False, "-A", default_args_str="")
        self.assertIn("-A", args_user_A.split())
        self.assertNotIn("-sV", args_user_A.split()[1:]) # -A implies -sV, so -sV shouldn't be added again

        # Case 3: GSettings provides -sV, user provides nothing that implies -sV
        args_gsettings_sV = self.scanner.build_scan_args(False, "-T4", default_args_str="-sV")
        self.assertIn("-sV", args_gsettings_sV.split())
        self.assertIn("-T4", args_gsettings_sV.split())
        
        # Case 4: GSettings provides -sV, user also provides -sV. Should only be one.
        args_both_sV = self.scanner.build_scan_args(False, "-sV -p 123", default_args_str="-sV --host-timeout=10s")
        self.assertEqual(args_both_sV.count("-sV"), 1, f"Args: {args_both_sV}")
        self.assertIn("-p", args_both_sV.split())
        self.assertIn("123", args_both_sV.split())
        self.assertIn("--host-timeout=10s", args_both_sV)


    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_with_nse_script(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance
        
        args = self.scanner.build_scan_args(False, "", nse_script="vuln", default_args_str="")
        self.assertIn("--script=vuln", args)

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_default_host_timeout_from_gsettings(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        # This default is now expected to come from GSettings via default_args_str
        args = self.scanner.build_scan_args(False, "", default_args_str="--host-timeout=60s")
        self.assertIn("--host-timeout=60s", args)

        # Test that it's NOT added if not in default_args_str
        args_no_timeout = self.scanner.build_scan_args(False, "", default_args_str="-T4")
        self.assertNotIn("--host-timeout", args_no_timeout)


    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_user_host_timeout_preserved(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance
        
        # User provides timeout in additional_args, GSettings default might or might not have it
        args_custom_s = self.scanner.build_scan_args(False, "--host-timeout=120s", default_args_str="")
        self.assertIn("--host-timeout=120s", args_custom_s)
        self.assertEqual(args_custom_s.count("--host-timeout"), 1)

        args_custom_ms = self.scanner.build_scan_args(False, "--host-timeout 30ms", default_args_str="-T1")
        self.assertIn("--host-timeout 30ms", args_custom_ms)
        self.assertTrue(any(arg.startswith("--host-timeout") for arg in args_custom_ms.split()))
        self.assertIn("30ms", args_custom_ms.split())
        self.assertIn("-T1", args_custom_ms.split()) # Ensure default arg is also there

        # User timeout should take precedence if GSettings also has one
        args_both_timeouts = self.scanner.build_scan_args(False, "--host-timeout=20s", default_args_str="--host-timeout=50s -sV")
        # shlex.split works on the string parts. User args are appended.
        # Nmap usually takes the last specified one.
        # Our build_scan_args concatenates: default_args + user_args
        # So, "--host-timeout=50s -sV --host-timeout=20s" (order might vary due to shlex)
        # We expect "--host-timeout=20s" to be the effective one if nmap uses the last.
        # The string will contain both if not carefully managed.
        # Current NmapScanner code simply concatenates lists from shlex.split.
        # This means both will be present in the string.
        self.assertIn("--host-timeout=20s", args_both_timeouts)
        self.assertIn("--host-timeout=50s", args_both_timeouts) # Both will be in the string
        self.assertIn("-sV", args_both_timeouts.split())


    def test_build_scan_args_shlex_split_failure_default_args(self):
        # Test shlex failure for default_args_str
        with self.assertRaisesRegex(NmapArgumentError, "Error parsing default arguments:"):
            self.scanner.build_scan_args(False, "", default_args_str="-sV 'mismatched_quote")

    def test_build_scan_args_shlex_split_failure_additional_args(self):
        # Test shlex failure for additional_args_str
        with self.assertRaisesRegex(NmapArgumentError, "Error parsing additional arguments:"):
            self.scanner.build_scan_args(False, "-sV 'mismatched_quote", default_args_str="")


    # --- New Tests for GSettings Interaction ---

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_dns_servers_empty(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        args = self.scanner.build_scan_args(False, "-T4", default_args_str="-sV")
        self.assertNotIn("--dns-servers", args)
        self.assertIn("-T4", args)
        self.assertIn("-sV", args)

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_dns_servers_single(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": "1.1.1.1"})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        args = self.scanner.build_scan_args(False, "-T4", default_args_str="-sV")
        self.assertIn("--dns-servers=1.1.1.1", args)
        self.assertIn("-T4", args)
        self.assertIn("-sV", args)

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_dns_servers_multiple(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": "8.8.8.8,1.1.1.1"})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        args = self.scanner.build_scan_args(False, "-T4", default_args_str="-sV")
        self.assertIn("--dns-servers=8.8.8.8,1.1.1.1", args)

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_dns_servers_with_spaces(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": " 8.8.8.8 , 1.1.1.1 , 4.4.4.4"})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        args = self.scanner.build_scan_args(False, "", default_args_str="")
        self.assertIn("--dns-servers=8.8.8.8,1.1.1.1,4.4.4.4", args)

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_dns_servers_already_in_additional_args(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": "1.1.1.1"})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        # User provides --dns-servers in additional_args_str
        args = self.scanner.build_scan_args(False, "--dns-servers 9.9.9.9", default_args_str="")
        # GSettings should be ignored, user's arg takes precedence (or rather, GSettings one is not added)
        self.assertIn("--dns-servers 9.9.9.9", args) # From additional_args
        self.assertNotIn("1.1.1.1", args) # From GSettings, should not be added
        # Check that the argument appears only once
        self.assertEqual(args.count("--dns-servers"), 1)


    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_gsettings_default_args_empty(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""}) # No DNS
        mock_gio_settings_constructor.return_value = mock_settings_instance
        
        # Pass empty string for default_args_str, simulating empty GSettings for "default-nmap-arguments"
        args = self.scanner.build_scan_args(False, "-Pn", default_args_str="")
        self.assertIn("-Pn", args.split())
        self.assertNotIn("-sV", args.split()) # Old hardcoded default
        self.assertFalse(any(a.startswith("--host-timeout") for a in args.split())) # Old hardcoded default

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_gsettings_default_args_custom(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        gsettings_defaults = "-T4 -F --reason"
        args = self.scanner.build_scan_args(False, "-O", default_args_str=gsettings_defaults)
        args_list = args.split()
        self.assertIn("-T4", args_list)
        self.assertIn("-F", args_list)
        self.assertIn("--reason", args_list)
        self.assertIn("-O", args_list) # From additional_args_str
        self.assertNotIn("-sV", args_list) # Old hardcoded, should not be there unless in gsettings_defaults
        self.assertFalse(any(a.startswith("--host-timeout") for a in args_list))


    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_gsettings_includes_sV_and_timeout(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        gsettings_defaults = "-sV --host-timeout=90s -T3"
        args = self.scanner.build_scan_args(False, "", default_args_str=gsettings_defaults)
        args_list = args.split()
        self.assertIn("-sV", args_list)
        self.assertIn("--host-timeout=90s", args) # Check full string
        self.assertIn("-T3", args_list)

    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_interaction_gsettings_and_additional(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({"dns-servers": ""})
        mock_gio_settings_constructor.return_value = mock_settings_instance

        gsettings_defaults = "-T4 --datadir /tmp"
        additional_args = "-sL -p 80"
        # Expected: default args followed by user args
        args = self.scanner.build_scan_args(False, additional_args, default_args_str=gsettings_defaults)
        
        # Test presence of all parts
        self.assertIn("-T4", args)
        self.assertIn("--datadir /tmp", args) # This might be split by shlex if not careful, but join should restore
        self.assertIn("-sL", args)
        self.assertIn("-p 80", args)

        # Test order (additional args should come after default args if split by shlex and re-joined)
        # This is a bit fragile to test precisely without knowing shlex output for complex cases
        # A simple check:
        if "--datadir" in args and "-sL" in args: # Make sure both are there before find
             self.assertTrue(args.find("--datadir") < args.find("-sL") or args.find("/tmp") < args.find("-sL"), 
                            f"Order check failed for args: {args}")


    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_combined_dns_and_gsettings_defaults(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "dns-servers": "1.0.0.1,8.8.4.4",
            # "default-nmap-arguments" is passed via default_args_str for build_scan_args tests
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance

        gsettings_default_nmap_args = "-A -T5"
        args = self.scanner.build_scan_args(False, "-Pn", default_args_str=gsettings_default_nmap_args)
        
        self.assertIn("--dns-servers=1.0.0.1,8.8.4.4", args)
        self.assertIn("-A", args)
        self.assertIn("-T5", args)
        self.assertIn("-Pn", args) # From additional_args_str


    @patch('src.nmap_scanner.Gio.Settings')
    def test_build_scan_args_gsettings_retrieval_exception(self, mock_gio_settings_constructor):
        # Simulate Gio.Settings.new() or get_string() raising an exception for DNS servers
        mock_gio_settings_constructor.side_effect = Exception("GSettings schema not found")

        # When build_scan_args tries to get "dns-servers", it should catch the exception
        # and proceed without adding --dns-servers.
        # We expect a warning to be printed to stderr (can't easily check that without more mocking).
        args = self.scanner.build_scan_args(False, "-T0", default_args_str="-sC")
        
        self.assertNotIn("--dns-servers", args)
        self.assertIn("-T0", args)
        self.assertIn("-sC", args)


    # --- Tests for the scan() method (higher level, ensuring GSettings are fetched) ---

    @patch('src.nmap_scanner.nmap.PortScanner.scan') # Mock the actual nmap scan call
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_method_with_gsettings_dns_and_defaults(self, mock_gio_settings_constructor, mock_nmap_lib_scan):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "dns-servers": "1.1.1.1",
            "default-nmap-arguments": "-T4 -sV"
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance

        # Mock _parse_scan_results to return some valid data and avoid its internal logic
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))

        target = "example.com"
        additional_args = "-O --top-ports 10"
        self.scanner.scan(target, True, additional_args, nse_script="vulners")

        mock_nmap_lib_scan.assert_called_once()
        called_args_str = mock_nmap_lib_scan.call_args[1]['arguments']
        
        self.assertIn("--dns-servers=1.1.1.1", called_args_str)
        self.assertIn("-T4", called_args_str)    # From GSettings default
        self.assertIn("-sV", called_args_str)    # From GSettings default
        self.assertIn("-O", called_args_str)     # From additional_args (and do_os_fingerprint=True)
        self.assertIn("--top-ports 10", called_args_str) # From additional_args
        self.assertIn("--script=vulners", called_args_str) # From nse_script parameter

    @patch('src.nmap_scanner.nmap.PortScanner.scan')
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_method_gsettings_retrieval_exception(self, mock_gio_settings_constructor, mock_nmap_lib_scan):
        # Simulate Gio.Settings.new() raising an exception for default arguments
        mock_gio_settings_constructor.side_effect = Exception("Cannot connect to GSettings")

        self.scanner._parse_scan_results = MagicMock(return_value=([], None))
        
        target = "testhost.lan"
        additional_args = "-sP" # Simple ping scan
        self.scanner.scan(target, False, additional_args)

        mock_nmap_lib_scan.assert_called_once()
        called_args_str = mock_nmap_lib_scan.call_args[1]['arguments']

        # We expect that if GSettings fails, the scan proceeds with only other args.
        # DNS servers are also fetched via GSettings in build_scan_args, so that would also fail
        # or be skipped if the initial Gio.Settings.new in scan() fails.
        # If Gio.Settings.new in scan() fails, gsettings_default_args is None.
        # If Gio.Settings.new in build_scan_args() fails, --dns-servers is not added.
        
        self.assertNotIn("--dns-servers", called_args_str) # Should not be present if GSettings failed broadly
        self.assertNotIn("-T4", called_args_str) # Example default, should not be present
        self.assertNotIn("-sV", called_args_str) # Example default, should not be present
        self.assertIn("-sP", called_args_str)  # The user-provided arg should still be there.


    # --- Tests for pkexec logic in NmapScanner.scan() ---

    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_root', return_value=False) # User is NOT root
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_not_root_sS_uses_pkexec(self, mock_gio_settings_constructor, mock_is_root, mock_subprocess_run):
        # Configure GSettings mock
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "default-nmap-arguments": "", # No defaults that might add -sS
            "dns-servers": ""
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance
        
        # Configure subprocess.run mock to simulate a successful pkexec call
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="<?xml version=\"1.0\"?><nmaprun></nmaprun>", stderr="")
        # Mock analyse_nmap_xml_scan as it's called within the pkexec path
        self.scanner.nm.analyse_nmap_xml_scan = MagicMock()
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))


        # Call scan with stealth_scan=True, which should make build_scan_args add -sS
        self.scanner.scan("localhost", do_os_fingerprint=False, additional_args_str="", stealth_scan=True)

        mock_subprocess_run.assert_called_once()
        pkexec_cmd_list = mock_subprocess_run.call_args[0][0]
        self.assertEqual(pkexec_cmd_list[0], "pkexec")
        self.assertIn("-sS", pkexec_cmd_list)
        self.scanner.nm.scan.assert_not_called() # Direct nmap scan should not be called

    @patch('src.nmap_scanner.nmap.PortScanner.scan') # Mock the direct nmap library call
    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_root', return_value=True) # User IS root
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_is_root_sS_no_pkexec(self, mock_gio_settings_constructor, mock_is_root, mock_subprocess_run, mock_direct_nmap_scan_method):
        # self.scanner.nm.scan is the one to check for direct calls. Let's re-assign to the passed mock.
        self.scanner.nm.scan = mock_direct_nmap_scan_method

        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "default-nmap-arguments": "", "dns-servers": ""
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))

        self.scanner.scan("localhost", do_os_fingerprint=False, additional_args_str="", stealth_scan=True)

        mock_subprocess_run.assert_not_called()
        self.scanner.nm.scan.assert_called_once()
        called_args_str = self.scanner.nm.scan.call_args.kwargs['arguments']
        self.assertIn("-sS", called_args_str)

    @patch('src.nmap_scanner.nmap.PortScanner.scan')
    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_root', return_value=False) # User is NOT root
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_not_root_no_sS_no_os_no_pkexec(self, mock_gio_settings_constructor, mock_is_root, mock_subprocess_run, mock_direct_nmap_scan_method):
        self.scanner.nm.scan = mock_direct_nmap_scan_method
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "default-nmap-arguments": "", "dns-servers": ""
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))

        self.scanner.scan("localhost", do_os_fingerprint=False, additional_args_str="-T4", stealth_scan=False)

        mock_subprocess_run.assert_not_called()
        self.scanner.nm.scan.assert_called_once()
        called_args_str = self.scanner.nm.scan.call_args.kwargs['arguments']
        self.assertNotIn("-sS", called_args_str)
        self.assertNotIn("-O", called_args_str)

    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_root', return_value=False) # User is NOT root
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_not_root_os_fingerprint_uses_pkexec(self, mock_gio_settings_constructor, mock_is_root, mock_subprocess_run):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "default-nmap-arguments": "", "dns-servers": ""
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="<?xml version=\"1.0\"?><nmaprun></nmaprun>", stderr="")
        self.scanner.nm.analyse_nmap_xml_scan = MagicMock()
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))

        self.scanner.scan("localhost", do_os_fingerprint=True, additional_args_str="", stealth_scan=False)

        mock_subprocess_run.assert_called_once()
        pkexec_cmd_list = mock_subprocess_run.call_args[0][0]
        self.assertEqual(pkexec_cmd_list[0], "pkexec")
        self.assertIn("-O", pkexec_cmd_list)
        self.scanner.nm.scan.assert_not_called()

    @patch('src.nmap_scanner.nmap.PortScanner.scan')
    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_root', return_value=True) # User IS root
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_is_root_os_fingerprint_no_pkexec(self, mock_gio_settings_constructor, mock_is_root, mock_subprocess_run, mock_direct_nmap_scan_method):
        self.scanner.nm.scan = mock_direct_nmap_scan_method
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "default-nmap-arguments": "", "dns-servers": ""
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))

        self.scanner.scan("localhost", do_os_fingerprint=True, additional_args_str="", stealth_scan=False)

        mock_subprocess_run.assert_not_called()
        self.scanner.nm.scan.assert_called_once()
        called_args_str = self.scanner.nm.scan.call_args.kwargs['arguments']
        self.assertIn("-O", called_args_str)

    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_root', return_value=False) # User is NOT root
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_not_root_os_fingerprint_and_sS_uses_pkexec(self, mock_gio_settings_constructor, mock_is_root, mock_subprocess_run):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "default-nmap-arguments": "", "dns-servers": ""
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="<?xml version=\"1.0\"?><nmaprun></nmaprun>", stderr="")
        self.scanner.nm.analyse_nmap_xml_scan = MagicMock()
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))

        self.scanner.scan("localhost", do_os_fingerprint=True, additional_args_str="", stealth_scan=True)

        mock_subprocess_run.assert_called_once()
        pkexec_cmd_list = mock_subprocess_run.call_args[0][0]
        self.assertEqual(pkexec_cmd_list[0], "pkexec")
        self.assertIn("-O", pkexec_cmd_list)
        self.assertIn("-sS", pkexec_cmd_list)
        self.scanner.nm.scan.assert_not_called()

    # --- End of pkexec logic Tests ---

# Separate class for testing the _execute_with_privileges method and its integration in scan()
class TestNmapScannerPrivilegeExecution(unittest.TestCase):
    def setUp(self):
        # We need a scanner instance.
        # Since __init__ now calls shutil.which, we might need to patch it globally for this test class
        # if we don't want actual file system checks during setup.
        # For now, let's assume NmapScanner() can be instantiated; specific tests will patch shutil.which as needed.
        with patch('src.nmap_scanner.shutil.which', return_value='/fake/nmap'): # Default mock for setup
            self.scanner = NmapScanner()
        self.scanner.nm = MagicMock() # Mock the PortScanner object within NmapScanner

    def _configure_gsettings_mock(self, mock_gio_settings_constructor, defaults=None, dns=""):
        if defaults is None:
            defaults = "" # Default to empty string for nmap arguments
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = lambda key: defaults if key == "default-nmap-arguments" else dns if key == "dns-servers" else ""
        mock_gio_settings_constructor.return_value = mock_settings_instance
        return mock_settings_instance

    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_flatpak', return_value=False)
    @patch('src.nmap_scanner.is_linux', return_value=False)
    @patch('src.nmap_scanner.is_macos', return_value=True)
    def test_execute_privileges_macos(self, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")
        nmap_base = ['/usr/local/bin/nmap']
        scan_args = ['-sS', '-p', '80']
        target = 'localhost'
        
        # Expected Nmap command string for AppleScript
        # shlex.join will handle spaces in args if any: e.g., shlex.join(['nmap', '--script', 'http-title, "safe space"'])
        # -> "nmap --script 'http-title, \"safe space\"'" or similar.
        # Then, internal quotes are escaped: "nmap --script 'http-title, \\\"safe space\\\"'"
        expected_nmap_cmd_str = '/usr/local/bin/nmap -sS -p 80 localhost' # Simple case, no complex quoting by shlex.join
        expected_applescript_cmd = f'do shell script "{expected_nmap_cmd_str.replace("\"", "\\\"")}" with administrator privileges'

        self.scanner._execute_with_privileges(nmap_base, scan_args, target)
        
        mock_subprocess_run.assert_called_once()
        called_cmd = mock_subprocess_run.call_args[0][0]
        self.assertEqual(called_cmd[0], "osascript")
        self.assertEqual(called_cmd[1], "-e")
        self.assertEqual(called_cmd[2], expected_applescript_cmd)

    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_flatpak', return_value=False)
    @patch('src.nmap_scanner.is_linux', return_value=False)
    @patch('src.nmap_scanner.is_macos', return_value=True)
    def test_execute_privileges_macos_complex_args(self, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")
        nmap_base = ['/usr/local/bin/nmap']
        # Argument that shlex.join will likely quote: an argument with a space
        scan_args = ['--script-args', 'http.useragent="My Nmap Agent 1.0"'] 
        target = 'localhost'
        
        # How shlex.join might format it: /usr/local/bin/nmap --script-args 'http.useragent="My Nmap Agent 1.0"' localhost
        # Then replace('"', '\\"') makes it: /usr/local/bin/nmap --script-args 'http.useragent=\\\"My Nmap Agent 1.0\\\"' localhost
        # This seems correct for AppleScript's `do shell script "..."`
        joined_nmap_cmd = shlex.join(nmap_base + scan_args + [target])
        expected_applescript_cmd = f'do shell script "{joined_nmap_cmd.replace("\"", "\\\"")}" with administrator privileges'

        self.scanner._execute_with_privileges(nmap_base, scan_args, target)
        
        mock_subprocess_run.assert_called_once()
        called_cmd = mock_subprocess_run.call_args[0][0]
        self.assertEqual(called_cmd[0], "osascript")
        self.assertEqual(called_cmd[2], expected_applescript_cmd)


    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_flatpak', return_value=True)
    @patch('src.nmap_scanner.is_linux', return_value=True) # is_flatpak should take precedence
    @patch('src.nmap_scanner.is_macos', return_value=False)
    def test_execute_privileges_flatpak(self, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")
        nmap_base = ['nmap'] # Typically 'nmap' for flatpak-spawn --host
        scan_args = ['-O']
        target = 'host2'
        
        self.scanner._execute_with_privileges(nmap_base, scan_args, target)
        expected_cmd = ['flatpak-spawn', '--host', 'pkexec', 'nmap', '-O', 'host2']
        mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=False)

    @patch('src.nmap_scanner.subprocess.run')
    @patch('src.nmap_scanner.is_flatpak', return_value=False)
    @patch('src.nmap_scanner.is_linux', return_value=True)
    @patch('src.nmap_scanner.is_macos', return_value=False)
    def test_execute_privileges_linux(self, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_subprocess_run):
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")
        nmap_base = ['/usr/bin/nmap']
        scan_args = ['-sU', '-p', '161']
        target = 'host3'

        self.scanner._execute_with_privileges(nmap_base, scan_args, target)
        expected_cmd = ['pkexec', '/usr/bin/nmap', '-sU', '-p', '161', 'host3']
        mock_subprocess_run.assert_called_once_with(expected_cmd, capture_output=True, text=True, check=False)

    @patch('src.nmap_scanner.sys.platform', "win32") # Mock sys.platform directly for unsupported
    @patch('src.nmap_scanner.is_flatpak', return_value=False)
    @patch('src.nmap_scanner.is_linux', return_value=False)
    @patch('src.nmap_scanner.is_macos', return_value=False)
    def test_execute_privileges_unsupported_os(self, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_sys_platform_val):
        # mock_sys_platform_val is not used directly, but sys.platform is patched
        nmap_base = ['nmap']
        scan_args = ['-T4']
        target = 'host4'

        result = self.scanner._execute_with_privileges(nmap_base, scan_args, target)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Privilege escalation not supported on this platform: win32", result.stderr)

    @patch('src.nmap_scanner.subprocess.run', side_effect=FileNotFoundError("pkexec not found"))
    @patch('src.nmap_scanner.is_flatpak', return_value=False)
    @patch('src.nmap_scanner.is_linux', return_value=True) # Simulate Linux for pkexec
    @patch('src.nmap_scanner.is_macos', return_value=False)
    def test_execute_privileges_escalation_tool_not_found(self, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_subprocess_run):
        nmap_base = ['/usr/bin/nmap']
        scan_args = ['-sS']
        target = 'host5'

        result = self.scanner._execute_with_privileges(nmap_base, scan_args, target)
        self.assertEqual(result.returncode, 127)
        self.assertIn("Escalation command 'pkexec' not found", result.stderr)

    # Tests for scan() method's determination of nmap_cmd_for_escalation
    @patch('src.nmap_scanner.NmapScanner._execute_with_privileges') # Spy on this method
    @patch('src.nmap_scanner.is_root', return_value=False) # Needs escalation
    @patch('src.nmap_scanner.shutil.which')
    @patch('src.nmap_scanner.is_flatpak', return_value=False)
    @patch('src.nmap_scanner.is_linux', return_value=False)
    @patch('src.nmap_scanner.is_macos', return_value=True)
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_macos_nmap_path_found(self, mock_gio_settings, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_shutil_which, mock_is_root, mock_execute_priv):
        self._configure_gsettings_mock(mock_gio_settings)
        mock_shutil_which.return_value = '/opt/local/bin/nmap'
        self.scanner.nm.analyse_nmap_xml_scan = MagicMock() # Avoid issues with parsing None
        self.scanner._parse_scan_results = MagicMock(return_value=([], None)) # Avoid issues
        mock_execute_priv.return_value = MagicMock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")


        self.scanner.scan("localhost", do_os_fingerprint=True, additional_args_str="") # OS fingerprint needs root
        mock_execute_priv.assert_called_once()
        called_nmap_base_cmd_list = mock_execute_priv.call_args[0][0]
        self.assertEqual(called_nmap_base_cmd_list, ['/opt/local/bin/nmap'])

    @patch('src.nmap_scanner.NmapScanner._execute_with_privileges')
    @patch('src.nmap_scanner.is_root', return_value=False)
    @patch('src.nmap_scanner.shutil.which')
    @patch('src.nmap_scanner.is_flatpak', return_value=False)
    @patch('src.nmap_scanner.is_linux', return_value=False)
    @patch('src.nmap_scanner.is_macos', return_value=True)
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_macos_nmap_path_fallback(self, mock_gio_settings, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_shutil_which, mock_is_root, mock_execute_priv):
        self._configure_gsettings_mock(mock_gio_settings)
        mock_shutil_which.return_value = None # Simulate nmap not in PATH
        self.scanner.nm.analyse_nmap_xml_scan = MagicMock()
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))
        mock_execute_priv.return_value = MagicMock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")

        self.scanner.scan("localhost", do_os_fingerprint=True, additional_args_str="")
        mock_execute_priv.assert_called_once()
        called_nmap_base_cmd_list = mock_execute_priv.call_args[0][0]
        self.assertEqual(called_nmap_base_cmd_list, ['/usr/local/bin/nmap']) # Default for macOS

    @patch('src.nmap_scanner.NmapScanner._execute_with_privileges')
    @patch('src.nmap_scanner.is_root', return_value=False)
    @patch('src.nmap_scanner.shutil.which')
    @patch('src.nmap_scanner.is_flatpak', return_value=False)
    @patch('src.nmap_scanner.is_linux', return_value=True) # Linux, not Flatpak
    @patch('src.nmap_scanner.is_macos', return_value=False)
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_linux_nmap_path_fallback(self, mock_gio_settings, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_shutil_which, mock_is_root, mock_execute_priv):
        self._configure_gsettings_mock(mock_gio_settings)
        mock_shutil_which.return_value = None # Simulate nmap not in PATH
        self.scanner.nm.analyse_nmap_xml_scan = MagicMock()
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))
        mock_execute_priv.return_value = MagicMock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")

        self.scanner.scan("localhost", do_os_fingerprint=True, additional_args_str="")
        mock_execute_priv.assert_called_once()
        called_nmap_base_cmd_list = mock_execute_priv.call_args[0][0]
        self.assertEqual(called_nmap_base_cmd_list, ['/usr/bin/nmap']) # Default for Linux

    @patch('src.nmap_scanner.NmapScanner._execute_with_privileges')
    @patch('src.nmap_scanner.is_root', return_value=False)
    @patch('src.nmap_scanner.shutil.which') # Should ideally not be called for flatpak path logic for escalation
    @patch('src.nmap_scanner.is_flatpak', return_value=True) # Flatpak
    @patch('src.nmap_scanner.is_linux', return_value=True) # is_flatpak takes precedence
    @patch('src.nmap_scanner.is_macos', return_value=False)
    @patch('src.nmap_scanner.Gio.Settings')
    def test_scan_flatpak_nmap_path(self, mock_gio_settings, mock_is_macos, mock_is_linux, mock_is_flatpak, mock_shutil_which, mock_is_root, mock_execute_priv):
        self._configure_gsettings_mock(mock_gio_settings)
        self.scanner.nm.analyse_nmap_xml_scan = MagicMock()
        self.scanner._parse_scan_results = MagicMock(return_value=([], None))
        mock_execute_priv.return_value = MagicMock(returncode=0, stdout="<nmaprun></nmaprun>", stderr="")

        self.scanner.scan("localhost", do_os_fingerprint=True, additional_args_str="")
        mock_execute_priv.assert_called_once()
        called_nmap_base_cmd_list = mock_execute_priv.call_args[0][0]
        self.assertEqual(called_nmap_base_cmd_list, ['nmap']) # 'nmap' for flatpak-spawn --host
        # Verify shutil.which was NOT called in the Flatpak path determination for escalation cmd
        # This depends on the implementation detail in scan()
        # The current implementation of scan() for flatpak defaults to 'nmap' for nmap_cmd_for_escalation
        # without calling shutil.which in that specific branch.
        # So, if is_flatpak() is true, shutil.which should not be called for determining nmap_cmd_for_escalation
        # (it might be called by NmapScanner.__init__ though, so clear its mock if needed for this specific check)
        # For this test, we are interested in the args to _execute_with_privileges.
        # It's simpler to just assert the argument.

    @patch('src.nmap_scanner.is_root', return_value=False) # User is NOT root
    @patch('src.nmap_scanner.is_macos', return_value=False) # Assume Linux non-Flatpak for escalation path
    @patch('src.nmap_scanner.is_linux', return_value=True)
    @patch('src.nmap_scanner.is_flatpak', return_value=False)
    @patch('src.nmap_scanner.shutil.which', return_value='/usr/bin/nmap') # Mock shutil.which
    @patch('src.nmap_scanner.Gio.Settings') # Mock GSettings
    def test_scan_not_root_O_in_text_args_uses_priv_esc(self, mock_gio_settings_constructor, 
                                                           mock_shutil_which, 
                                                           mock_is_flatpak, mock_is_linux, mock_is_macos, 
                                                           mock_is_root):
        # Configure GSettings to return empty default arguments
        self._configure_gsettings_mock(mock_gio_settings_constructor, defaults="")
        
        # Spy on the _execute_with_privileges method of the instance
        with patch.object(self.scanner, '_execute_with_privileges', 
                          return_value=MagicMock(spec=subprocess.CompletedProcess, 
                                                 returncode=0, stdout="<nmaprun></nmaprun>", stderr="")) as mock_execute_method:
            
            # Mock methods called after _execute_with_privileges or if it's not called
            self.scanner.nm.analyse_nmap_xml_scan = MagicMock()
            self.scanner._parse_scan_results = MagicMock(return_value=([], None))

            self.scanner.scan(
                target="localhost",
                do_os_fingerprint=False,  # Explicitly False for this test's purpose
                additional_args_str="-O", # -O is provided as a text argument
                nse_script=None,
                stealth_scan=False, # Ensure -sS is not also triggering escalation
                port_spec=None,
                timing_template=None,
                no_ping=False
            )

            mock_execute_method.assert_called_once()
            # Verify that "-O" was in the arguments passed to _execute_with_privileges
            args, kwargs = mock_execute_method.call_args
            # args[0] is nmap_base_cmd_list, args[1] is scan_args_list
            passed_scan_args_list = args[1] 
            self.assertIn("-O", passed_scan_args_list)
            # Ensure -sS is not present if stealth_scan was False, to isolate -O as the cause
            self.assertNotIn("-sS", passed_scan_args_list)


    # --- End of New GSettings Tests ---


    def test_parse_results_with_udp_port_data(self):
        mock_host_ip = '192.168.1.3'
        mock_host_scan_data_dict = {
            'hostname': 'udphost.local',
            'state': {'state': 'up'}, # type: ignore
            'protocols': { # type: ignore
                'udp': { # type: ignore
                    53: {'state': 'open|filtered', 'name': 'domain'}, # type: ignore
                    161: {'state': 'open', 'name': 'snmp', 'product': 'SNMPv1 server'} # type: ignore
                }
            }
        }
        self.scanner.nm.all_hosts.return_value = [mock_host_ip]
        self.scanner.nm.__getitem__.return_value = PortScannerHostDict(mock_host_scan_data_dict)
        
        hosts_data, error_message = self.scanner._parse_scan_results(do_os_fingerprint=False)
        
        self.assertIsNone(error_message)
        self.assertEqual(len(hosts_data), 1)
        host_result = hosts_data[0]
        self.assertEqual(len(host_result['ports']), 2)
        
        dns_port = next(p for p in host_result['ports'] if p['portid'] == 53)
        self.assertEqual(dns_port['protocol'], 'udp')
        self.assertEqual(dns_port['state'], 'open|filtered')

        snmp_port = next(p for p in host_result['ports'] if p['portid'] == 161)
        self.assertEqual(snmp_port['protocol'], 'udp')
        self.assertEqual(snmp_port['service']['product'], 'SNMPv1 server')
        self.assertIn("Port: 53/udp", host_result['raw_details_text'])


    def test_parse_results_protocol_with_no_port_entries(self):
        mock_host_ip = '192.168.1.4'
        mock_host_scan_data_dict = { # type: ignore
            'hostname': 'noports.local', # type: ignore
            'state': {'state': 'up'}, # type: ignore
            'protocols': {'tcp': {}} # TCP protocol listed, but no ports # type: ignore
        }
        self.scanner.nm.all_hosts.return_value = [mock_host_ip]
        self.scanner.nm.__getitem__.return_value = PortScannerHostDict(mock_host_scan_data_dict)

        hosts_data, error_message = self.scanner._parse_scan_results(do_os_fingerprint=False)

        self.assertIsNone(error_message)
        host_result = hosts_data[0]
        self.assertEqual(len(host_result['ports']), 0)
        self.assertIn("Protocol: TCP", host_result['raw_details_text'])
        self.assertIn("No open ports found for this protocol.", host_result['raw_details_text'])

    def test_parse_results_os_fingerprint_no_matches(self):
        mock_host_ip = '192.168.1.5'
        # Case 1: 'osmatch' key present but list is empty
        mock_data_empty_osmatch = {'hostname': 'noos1','state':{'state':'up'}, 'protocols':{}, 'osmatch': []}
        self.scanner.nm.all_hosts.return_value = [mock_host_ip]
        self.scanner.nm.__getitem__.return_value = PortScannerHostDict(mock_data_empty_osmatch) # type: ignore
        hosts_data, _ = self.scanner._parse_scan_results(do_os_fingerprint=True)
        self.assertIsNone(hosts_data[0]['os_fingerprint'])
        self.assertIn("OS Fingerprint: No OS matches found.", hosts_data[0]['raw_details_text'])

        # Case 2: 'osmatch' key not present
        mock_data_no_osmatch_key = {'hostname': 'noos2','state':{'state':'up'}, 'protocols':{}} # type: ignore
        self.scanner.nm.__getitem__.return_value = PortScannerHostDict(mock_data_no_osmatch_key) # type: ignore
        hosts_data, _ = self.scanner._parse_scan_results(do_os_fingerprint=True)
        self.assertIsNone(hosts_data[0]['os_fingerprint'])
        # If 'osmatch' is not present AND do_os_fingerprint is true, the "OS Fingerprint:" header
        # for raw_details_text might not be added. This is fine.
        # The check `host_info["os_fingerprint"] is None` is more important.
        # Let's verify if the current code adds "OS Fingerprint:" section if osmatch is missing
        # Current code: if do_os_fingerprint and "osmatch" in host_scan_data: ... else if do_os_fingerprint:
        # This means if 'osmatch' is not in host_scan_data, it won't add "No OS matches found."
        # It will simply not have an OS section. This is acceptable.
        self.assertNotIn("OS Fingerprint:", hosts_data[0]['raw_details_text'])


    def test_parse_results_key_error_on_host_data(self):
        mock_host_ip = '192.168.1.6'
        # Data that will cause host_scan_data.hostname() to fail if not robustly mocked
        malformed_ps_dict_data = {'state': {'state': 'up'}} # Missing 'hostname'
        
        self.scanner.nm.all_hosts.return_value = [mock_host_ip]
        
        # Mock PortScannerHostDict to simulate a KeyError when hostname() is called
        mock_host_obj = PortScannerHostDict(malformed_ps_dict_data)
        # To precisely simulate the error, we can make the .hostname() method itself raise KeyError
        # This requires the mock PortScannerHostDict to be more sophisticated or to mock its methods
        
        # Re-mocking the specific instance's method to raise error
        def faulty_hostname():
            raise KeyError("Simulated missing hostname data")
        
        # Create a MagicMock that can have its methods individually mocked
        # This replaces the simple PortScannerHostDict for this test case
        detailed_mock_host_obj = MagicMock(spec=PortScannerHostDict)
        detailed_mock_host_obj.hostname.side_effect = faulty_hostname # type: ignore
        # Need to provide other methods that are called before the error, if any.
        # .state() is called after .hostname() in current implementation for raw_details_parts.
        # However, the error should occur on .hostname() first.
        # .all_protocols() is called before .hostname() for the host_info dict.
        detailed_mock_host_obj.all_protocols.return_value = [] # Assume no protocols for simplicity # type: ignore

        self.scanner.nm.__getitem__.return_value = detailed_mock_host_obj
        
        with self.assertRaisesRegex(NmapScanParseError, "Error parsing data for host 192.168.1.6: Missing key"):
            self.scanner._parse_scan_results(do_os_fingerprint=False)


    @patch('src.nmap_scanner.Gio.Settings') # Mock GSettings for the scan method
    def test_scan_successful_with_nse_script(self, mock_gio_settings_constructor):
        mock_settings_instance = MagicMock()
        mock_settings_instance.get_string.side_effect = self._mock_gsettings_get_string({
            "default-nmap-arguments": "-sV", # Provide some default
            "dns-servers": ""
        })
        mock_gio_settings_constructor.return_value = mock_settings_instance

        target_host = "testhost.com"
        nse_script_name = "http-title"
        additional_args = "-p 80"
        
        # Mock self.nm.scan() itself as it's an external call
        self.scanner.nm.scan = MagicMock()
        
        expected_parsed_data = [{"id": target_host, "hostname": target_host, "state": "up", "ports": []}]
        # Mock _parse_scan_results to avoid actual parsing logic in this integration test
        self.scanner._parse_scan_results = MagicMock(return_value=(expected_parsed_data, None))
        
        result_data, error_msg = self.scanner.scan(target_host, False, additional_args, nse_script=nse_script_name)
        
        self.assertIsNone(error_msg)
        self.assertEqual(result_data, expected_parsed_data)
        
        # Verify nm.scan was called with arguments including the script
        self.scanner.nm.scan.assert_called_once()
        call_args_list = self.scanner.nm.scan.call_args_list
        self.assertEqual(len(call_args_list), 1)
        call_kwargs = call_args_list[0][1] # Get kwargs of the first call

        self.assertEqual(call_kwargs.get('hosts'), target_host)
        called_scan_args_str = call_kwargs.get('arguments', '')
        self.assertIn(f"--script={nse_script_name}", called_scan_args_str)
        self.assertIn(additional_args, called_scan_args_str)


    def test_scan_propagates_parse_error(self):
        target_host = "anotherhost.com"
        
        self.scanner.nm.scan = MagicMock() # Mock the actual Nmap execution
        
        parse_error_message = "Failed to parse due to critical reasons."
        # Configure the instance's _parse_scan_results to raise the error
        self.scanner._parse_scan_results = MagicMock(side_effect=NmapScanParseError(parse_error_message))
        
        result_data, error_msg = self.scanner.scan(target_host, False, "") # Call the main scan method
        
        self.assertIsNone(result_data)
        self.assertIsNotNone(error_msg)
        self.assertIn("Scan parsing error:", error_msg)
        self.assertIn(parse_error_message, error_msg)


    def test_parse_results_multiple_hosts(self):
        mock_host1_ip = '192.168.1.10'
        mock_scan1_data = {
            'hostname': 'host1.local', 'state': {'state':'up'},
            'protocols': {'tcp': {22: {'state': 'open', 'name': 'ssh'}}}
        }
        mock_host2_ip = '192.168.1.11'
        mock_scan2_data = {
            'hostname': 'host2.local', 'state': {'state':'down'},
            'protocols': {'tcp': {}} # No open TCP ports
        }

        self.scanner.nm.all_hosts.return_value = [mock_host1_ip, mock_host2_ip]
        
        mock_host_objects = {
            mock_host1_ip: PortScannerHostDict(mock_scan1_data),
            mock_host2_ip: PortScannerHostDict(mock_scan2_data)
        }
        self.scanner.nm.__getitem__.side_effect = lambda host_ip: mock_host_objects[host_ip]
        
        hosts_data, error_message = self.scanner._parse_scan_results(do_os_fingerprint=False)

        self.assertIsNone(error_message)
        self.assertEqual(len(hosts_data), 2)
        
        host1_result = next(h for h in hosts_data if h['id'] == mock_host1_ip)
        self.assertEqual(host1_result['hostname'], 'host1.local')
        self.assertEqual(len(host1_result['ports']), 1)

        host2_result = next(h for h in hosts_data if h['id'] == mock_host2_ip)
        self.assertEqual(host2_result['hostname'], 'host2.local')
        self.assertEqual(len(host2_result['ports']), 0)


if __name__ == '__main__':
    unittest.main()
