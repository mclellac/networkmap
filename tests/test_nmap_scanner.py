import unittest
from unittest.mock import patch, MagicMock, mock_open
import subprocess
import sys
import os
import nmap # Import the actual nmap to allow specing PortScanner

# Adjust import path to allow src modules to be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from nmap_scanner import NmapScanner, NmapArgumentError, NmapScanParseError

# Mock gi.repository for tests running outside a GI environment
# This is crucial because NmapScanner imports Gio and GLib from gi.repository
try:
    from gi.repository import Gio, GLib
except ImportError:
    # Create detailed mock objects for Gio.Settings and GLib
    # This allows the NmapScanner module to be imported and tests to run
    # in environments where GTK/GNOME libraries are not fully installed or set up.
    
    MockGioSettingsInstance = MagicMock()
    MockGioSettingsInstance.get_string.return_value = "" # Default for any string setting
    MockGioSettingsInstance.get_strv.return_value = []   # Default for any string list setting
    MockGioSettingsInstance.get_boolean.return_value = False # Default for any boolean
    # Add other methods like set_string, set_strv etc. if NmapScanner writes settings (not typical)

    MockGio = MagicMock()
    MockGio.Settings = MagicMock()
    MockGio.Settings.new = MagicMock(return_value=MockGioSettingsInstance) # Return the instance
    
    MockGLib = MagicMock()
    # GLib.markup_escape_text is used in _parse_scan_results
    MockGLib.markup_escape_text = lambda text: str(text) # Simple pass-through

    sys.modules['gi.repository.Gio'] = MockGio
    sys.modules['gi.repository.GLib'] = MockGLib
    Gio = MockGio # Make it available in the global scope of this file for NmapScanner
    GLib = MockGLib # Make it available


# Sample Nmap XML output for testing _parse_scan_results
SAMPLE_NMAP_XML_OUTPUT_SINGLE_HOST = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - -T4 -sV localhost" start="1678886400" startstr="Sat Mar 15 12:00:00 2023" version="7.93" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1" services="22"/>
<host starttime="1678886400" endtime="1678886401"><status state="up" reason="localhost-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="80"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="http" method="table" conf="3"/></port>
</ports>
<os>
<osmatch name="Linux 5.4.0-135-generic" accuracy="100" line="65420">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="100"><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass>
</osmatch>
</os>
<times srtt="123" rttvar="456" to="100000"/>
</host>
<runstats><finished time="1678886401" summary="Nmap done at Sat Mar 15 12:00:01 2023; 1 IP address (1 host up) scanned in 1.00 seconds" elapsed="1.00" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""

SAMPLE_NMAP_XML_NO_HOSTS = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - 192.168.1.250" start="1678886400" version="7.93">
<runstats><finished time="1678886403" elapsed="3.00"/><hosts up="0" down="1" total="1"/>
</runstats>
</nmaprun>
"""

class TestNmapScanner(unittest.TestCase):

    def setUp(self):
        # Mock Gio.Settings for NmapScanner's internal use (e.g. default_args_str, dns-servers)
        self.mock_gsettings_instance = MagicMock(spec=Gio.Settings)
        self.mock_gsettings_instance.get_string.side_effect = lambda key: {
            "default-nmap-arguments": "", # Default to no default args
            "dns-servers": ""             # Default to no specific DNS servers
        }.get(key, "")

        self.gio_settings_patcher = patch('gi.repository.Gio.Settings.new', return_value=self.mock_gsettings_instance)
        self.mock_gio_settings_new_class = self.gio_settings_patcher.start()
        
        self.shutil_which_patcher = patch('shutil.which')
        self.mock_shutil_which = self.shutil_which_patcher.start()
        self.mock_shutil_which.return_value = '/usr/bin/nmap' # Assume nmap is found

        # Patch os.path.exists and os.access for _find_nmap_executable_or_raise logic
        self.os_path_exists_patcher = patch('os.path.exists', return_value=True)
        self.mock_os_path_exists = self.os_path_exists_patcher.start()
        self.os_access_patcher = patch('os.access', return_value=True)
        self.mock_os_access = self.os_access_patcher.start()

        self.scanner = NmapScanner()
        self.scanner.nm = MagicMock(spec=nmap.PortScanner) # Mock the PortScanner instance

    def tearDown(self):
        self.gio_settings_patcher.stop()
        self.shutil_which_patcher.stop()
        self.os_path_exists_patcher.stop()
        self.os_access_patcher.stop()

    # --- Tests for _find_nmap_executable_or_raise ---
    def test_find_nmap_executable_found_in_path(self):
        self.mock_shutil_which.return_value = "/custom/path/nmap"
        scanner = NmapScanner()
        self.assertEqual(scanner.nmap_executable_path, "/custom/path/nmap")

    def test_find_nmap_executable_found_in_common_paths_linux(self):
        self.mock_shutil_which.return_value = None # Not in PATH
        with patch('nmap_scanner.is_linux', return_value=True), \
             patch('nmap_scanner.is_macos', return_value=False):
            self.mock_os_path_exists.side_effect = lambda p: p == '/usr/bin/nmap'
            scanner = NmapScanner()
            self.assertEqual(scanner.nmap_executable_path, '/usr/bin/nmap')

    def test_find_nmap_executable_not_found(self):
        self.mock_shutil_which.return_value = None
        self.mock_os_path_exists.return_value = False # Not in common paths either
        with self.assertRaises(NmapArgumentError) as context:
            NmapScanner()
        self.assertIn("Nmap executable not found", str(context.exception))
        
    # --- Tests for build_scan_args ---
    def test_build_scan_args_only_additional(self):
        args = self.scanner.build_scan_args(False, "-sV -T4")
        self.assertEqual(args, "-sV -T4")

    def test_build_scan_args_with_os_fingerprint(self):
        args = self.scanner.build_scan_args(True, "-sV")
        self.assertIn("-O", args.split())
        self.assertIn("-sV", args.split())

    def test_build_scan_args_with_nse_script(self):
        args = self.scanner.build_scan_args(False, "", nse_script="http-title,vulners")
        self.assertEqual(args, "--script=http-title,vulners")

    def test_build_scan_args_with_stealth_scan(self):
        args = self.scanner.build_scan_args(False, "", stealth_scan=True)
        self.assertIn("-sS", args.split())

    def test_build_scan_args_stealth_conflict_additional(self):
        # If -sT (TCP Connect scan) is in additional_args, -sS should not be added
        args = self.scanner.build_scan_args(False, "-sT", stealth_scan=True)
        self.assertIn("-sT", args.split())
        self.assertNotIn("-sS", args.split())

    def test_build_scan_args_ports_timing_no_ping(self):
        args = self.scanner.build_scan_args(False, "", port_spec="80,443", timing_template="-T5", no_ping=True)
        self.assertIn("-p 80,443", args)
        self.assertIn("-T5", args.split())
        self.assertIn("-Pn", args.split())

    def test_build_scan_args_with_gsettings_defaults(self):
        self.mock_gsettings_instance.get_string.side_effect = lambda key: {
            "default-nmap-arguments": "-A --datadir /custom/nmap_data",
            "dns-servers": "1.1.1.1,8.8.8.8"
        }.get(key, "")
        
        # Re-initialize scanner or directly set its default_args_str for this test
        # For this test, we assume build_scan_args receives default_args_str as a parameter
        args = self.scanner.build_scan_args(
            do_os_fingerprint=True, 
            additional_args_str="-sC",
            default_args_str="-A --datadir /custom/nmap_data" # Passed explicitly
        )
        parts = shlex.split(args)
        self.assertIn("-A", parts)
        self.assertIn("--datadir", parts)
        self.assertIn("/custom/nmap_data", parts)
        self.assertIn("-O", parts) # From do_os_fingerprint
        self.assertIn("-sC", parts) # From additional_args
        # DNS servers are added from GSettings directly if not present
        self.assertIn("--dns-servers=1.1.1.1,8.8.8.8", parts)


    def test_build_scan_args_empty_and_none_inputs(self):
        args = self.scanner.build_scan_args(
            do_os_fingerprint=False,
            additional_args_str="",
            nse_script=None,
            default_args_str=None,
            stealth_scan=False,
            port_spec=None,
            timing_template=None,
            no_ping=False
        )
        self.assertEqual(args, "") # Expect empty string if no options are set

    # --- Tests for _parse_scan_results ---
    def test_parse_scan_results_valid_xml(self):
        # Mock the PortScanner's internal state after analyse_nmap_xml_scan
        self.scanner.nm.all_hosts.return_value = ['127.0.0.1']
        # Construct a mock for the host data that nm[host_id] would return
        mock_host_obj = MagicMock()
        mock_host_obj.hostname.return_value = 'localhost'
        mock_host_obj.state.return_value = 'up'
        mock_host_obj.all_protocols.return_value = ['tcp']
        mock_host_obj.get.side_effect = lambda proto_name, default_val={}: \
            {'tcp': {
                22: {'state': 'open', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1'},
                80: {'state': 'closed', 'name': 'http'}
            }}.get(proto_name, default_val)
        
        mock_osmatch_data = [{
            'name': 'Linux 5.4.0-135-generic', 'accuracy': '100',
            'osclass': [{'type': 'general purpose', 'vendor': 'Linux', 'osfamily': 'Linux', 'osgen': '5.X', 'accuracy': '100'}]
        }]
        # Correctly mock access to 'osmatch' as if it were a dictionary key
        mock_host_obj.__contains__.side_effect = lambda key: key == 'osmatch' # For 'osmatch' in host_scan_data
        # Ensure that when host_scan_data.get("osmatch", []) is called, it returns our mock data
        # This requires a more nuanced side_effect for .get if it's used for multiple keys.
        # If .get is only used for 'osmatch' in the relevant part of parsing, this is simpler:
        # mock_host_obj.get.return_value = mock_osmatch_data # If only for osmatch
        # More general:
        def get_side_effect(key, default=None):
            if key == 'osmatch': return mock_osmatch_data
            if key == 'tcp': return {'tcp': {
                22: {'state': 'open', 'name': 'ssh', 'product': 'OpenSSH', 'version': '8.2p1'},
                80: {'state': 'closed', 'name': 'http'}
            }}.get('tcp')
            return default
        mock_host_obj.get.side_effect = get_side_effect


        self.scanner.nm.__getitem__.return_value = mock_host_obj

        hosts_data, message = self.scanner._parse_scan_results(do_os_fingerprint=True)
        
        self.assertIsNone(message)
        self.assertEqual(len(hosts_data), 1)
        host = hosts_data[0]
        self.assertEqual(host['id'], '127.0.0.1')
        self.assertEqual(host['hostname'], 'localhost')
        self.assertEqual(host['state'], 'up')
        self.assertEqual(len(host['ports']), 2) # ssh and http
        self.assertEqual(host['ports'][0]['portid'], 22)
        self.assertEqual(host['ports'][0]['service']['name'], 'ssh')
        self.assertIsNotNone(host['os_fingerprint'])
        self.assertEqual(host['os_fingerprint']['name'], 'Linux 5.4.0-135-generic')
        self.assertIn("<b>Host:</b> 127.0.0.1", host['raw_details_text'])
        self.assertIn("<b>Port:</b> 22/tcp", host['raw_details_text'])


    def test_parse_scan_results_no_hosts_found_xml(self):
        self.scanner.nm.all_hosts.return_value = [] # Simulate nmap finding no hosts
        hosts_data, message = self.scanner._parse_scan_results(False)
        self.assertEqual(hosts_data, [])
        self.assertEqual(message, "No hosts found.")

    def test_parse_scan_results_malformed_host_data(self):
        self.scanner.nm.all_hosts.return_value = ['10.0.0.1']
        # Simulate host_scan_data that might cause a KeyError or TypeError during parsing
        mock_malformed_host_obj = MagicMock()
        mock_malformed_host_obj.hostname.return_value = "test-host"
        mock_malformed_host_obj.state.return_value = "up"
        mock_malformed_host_obj.all_protocols.return_value = ["tcp"]
        # Simulate missing 'name' in service details, which _parse_scan_results expects
        mock_malformed_host_obj.get.return_value = {'tcp': {80: {'state': 'open'}}} # No 'name' for service
        self.scanner.nm.__getitem__.return_value = mock_malformed_host_obj

        with self.assertRaises(NmapScanParseError):
            self.scanner._parse_scan_results(False)

    # --- Tests for privilege escalation logic (_should_escalate, _execute_with_privileges) ---
    @patch('nmap_scanner.is_root', return_value=False) # Current user is not root
    def test_should_escalate_needs_escalation(self, mock_is_root):
        self.assertTrue(self.scanner._should_escalate(True, [])) # OS fingerprinting
        self.assertTrue(self.scanner._should_escalate(False, ['-sS'])) # SYN scan
        self.assertTrue(self.scanner._should_escalate(False, ['-A', '-sU'])) # UDP Scan

    @patch('nmap_scanner.is_root', return_value=True) # Current user is root
    def test_should_escalate_already_root(self, mock_is_root):
        self.assertFalse(self.scanner._should_escalate(True, []))
        self.assertFalse(self.scanner._should_escalate(False, ['-sS']))

    @patch('nmap_scanner.is_root', return_value=False)
    def test_should_escalate_unprivileged_flag(self, mock_is_root):
        # --unprivileged flag should prevent escalation even if other args would require it
        self.assertFalse(self.scanner._should_escalate(True, ['-O', '--unprivileged']))
        self.assertFalse(self.scanner._should_escalate(False, ['-sS', '--unprivileged']))

    @patch('subprocess.run')
    def test_execute_with_privileges_success(self, mock_subprocess_run):
        # Common setup for successful privileged execution
        mock_completed_process = MagicMock(spec=subprocess.CompletedProcess)
        mock_completed_process.returncode = 0
        mock_completed_process.stdout = "<nmaprun></nmaprun>" # Dummy XML output
        mock_completed_process.stderr = ""
        mock_subprocess_run.return_value = mock_completed_process

        with patch('nmap_scanner.is_linux', return_value=True), \
             patch('nmap_scanner.is_flatpak', return_value=False), \
             patch('nmap_scanner.is_macos', return_value=False):
            
            result = self.scanner._execute_with_privileges(
                self.scanner.nmap_executable_path, ["-T4", "-sS"], "testhost"
            )
            mock_subprocess_run.assert_called_once()
            called_cmd = mock_subprocess_run.call_args[0][0]
            self.assertIn("pkexec", called_cmd)
            self.assertIn(self.scanner.nmap_executable_path, called_cmd)
            self.assertIn("-T4", called_cmd)
            self.assertIn("testhost", called_cmd)
            self.assertEqual(result.returncode, 0)

    @patch('subprocess.run')
    def test_execute_with_privileges_failure_tool_not_found(self, mock_subprocess_run):
        mock_subprocess_run.side_effect = FileNotFoundError("Escalation tool not found")
        with patch('nmap_scanner.is_linux', return_value=True), \
             patch('nmap_scanner.is_flatpak', return_value=False), \
             patch('nmap_scanner.is_macos', return_value=False):
            
            result = self.scanner._execute_with_privileges(
                self.scanner.nmap_executable_path, ["-T4"], "testhost"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Escalation tool 'pkexec' not found", result.stderr)
            
    @patch('subprocess.run')
    def test_execute_with_privileges_nmap_path_validation(self, mock_subprocess_run):
        # Test that an invalid nmap_base_cmd raises NmapArgumentError
        with self.assertRaises(NmapArgumentError) as context:
            self.scanner._execute_with_privileges("/invalid/path/to/nmap", ["-T4"], "host")
        self.assertIn("is not a valid executable path", str(context.exception))

        # Mock nmap_executable_path to be non-executable for this specific test
        with patch.object(self.scanner, 'nmap_executable_path', '/usr/bin/nonexistentnmap'), \
             patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=False): # Simulate path exists but not executable
            with self.assertRaises(NmapArgumentError):
                 self.scanner._execute_with_privileges(self.scanner.nmap_executable_path, ["-T4"], "host")


    # --- Test main scan() method (integrating other components) ---
    @patch('nmap_scanner.NmapScanner._execute_with_privileges')
    @patch('nmap_scanner.NmapScanner._should_escalate', return_value=True) # Force escalation
    def test_scan_privileged_success_and_parsing(self, mock_should_escalate, mock_execute_privileges):
        mock_completed_process = MagicMock(spec=subprocess.CompletedProcess)
        mock_completed_process.returncode = 0
        mock_completed_process.stdout = SAMPLE_NMAP_XML_OUTPUT_SINGLE_HOST # Use detailed XML
        mock_completed_process.stderr = ""
        mock_execute_privileges.return_value = mock_completed_process

        # analyse_nmap_xml_scan is called on self.scanner.nm
        self.scanner.nm.analyse_nmap_xml_scan = MagicMock() 
        
        # We are testing the scan method's orchestration, assuming _parse_scan_results works (tested elsewhere)
        # So, we can let the actual _parse_scan_results run if analyse_nmap_xml_scan populates the mock scanner.nm correctly.
        # For more isolation, _parse_scan_results could also be mocked.
        # Let's ensure the internal state of self.scanner.nm is set up as analyse_nmap_xml_scan would do.
        # This is tricky as python-nmap's internal structure is complex.
        # A simpler approach for this integration test is to mock _parse_scan_results.
        parsed_data_expected = ([{'id': '127.0.0.1', 'hostname': 'localhost', 'state': 'up'}], None)
        with patch.object(self.scanner, '_parse_scan_results', return_value=parsed_data_expected) as mock_internal_parse:
            hosts, message = self.scanner.scan("localhost", do_os_fingerprint=True, additional_args_str="-sV")

            mock_should_escalate.assert_called_once()
            mock_execute_privileges.assert_called_once()
            # Check args passed to _execute_with_privileges to ensure -oX - was added
            actual_args_for_execute = mock_execute_privileges.call_args[0][1] # scan_args_list
            self.assertTrue(any(actual_args_for_execute[i] == "-oX" and actual_args_for_execute[i+1] == "-" 
                                for i in range(len(actual_args_for_execute)-1)))
            
            self.scanner.nm.analyse_nmap_xml_scan.assert_called_once_with(nmap_xml_output=SAMPLE_NMAP_XML_OUTPUT_SINGLE_HOST)
            mock_internal_parse.assert_called_once() # Ensure our mock was called
            self.assertEqual(hosts, parsed_data_expected[0])
            self.assertIsNone(message)

    @patch('nmap_scanner.NmapScanner._should_escalate', return_value=False) # Force direct scan
    def test_scan_direct_success_and_parsing(self, mock_should_escalate):
        self.scanner.nm.scan = MagicMock() # Mock the call to nmap.PortScanner().scan()
        
        # Simulate that self.scanner.nm state is populated by the scan call for _parse_scan_results
        # This means _parse_scan_results will use the mocked self.scanner.nm
        parsed_data_expected = ([{'id': 'testhost.direct', 'state': 'up'}], None)
        with patch.object(self.scanner, '_parse_scan_results', return_value=parsed_data_expected) as mock_internal_parse:
            hosts, message = self.scanner.scan("testhost.direct", False, "-T4")

            mock_should_escalate.assert_called_once()
            self.scanner.nm.scan.assert_called_once()
            self.assertEqual(self.scanner.nm.nmap_path, self.scanner.nmap_executable_path) # Check nmap_path was set
            mock_internal_parse.assert_called_once()
            self.assertEqual(hosts, parsed_data_expected[0])
            self.assertIsNone(message)
            
    @patch('nmap_scanner.NmapScanner._execute_with_privileges')
    @patch('nmap_scanner.NmapScanner._should_escalate', return_value=True)
    def test_scan_privileged_failed_execution(self, mock_should_escalate, mock_execute_privileges):
        mock_completed_process = MagicMock(spec=subprocess.CompletedProcess)
        mock_completed_process.returncode = 1 # Simulate failure
        mock_completed_process.stdout = ""
        mock_completed_process.stderr = "pkexec authentication failed"
        mock_execute_privileges.return_value = mock_completed_process

        hosts, message = self.scanner.scan("localhost", True, "")
        self.assertIsNone(hosts)
        self.assertIn("Authentication failed for privileged scan", message)

    @patch('nmap_scanner.NmapScanner._should_escalate', return_value=False)
    def test_scan_direct_nmap_lib_error(self, mock_should_escalate):
        # Simulate python-nmap library raising PortScannerError
        self.scanner.nm.scan.side_effect = nmap.PortScannerError("Nmap internal library error")
        
        with self.assertRaises(NmapArgumentError) as context: # Assuming it re-raises as NmapArgumentError for setup issues
             hosts, message = self.scanner.scan("target", False, "")
             # Depending on how the error is wrapped, we might check message instead
             if message: # If it returns a message instead of raising for this specific error
                 self.assertIsNone(hosts)
                 self.assertIn("Nmap execution error: Nmap internal library error", message)
             else: # If it raises
                  self.fail("Expected NmapArgumentError or message to be returned")
        # Check if the context exception is what we expect if it raises
        if context.exception: # Check if an exception was actually raised and caught
           self.assertIn("Nmap executable not found", str(context.exception))


if __name__ == '__main__':
    unittest.main()
