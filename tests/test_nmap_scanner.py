import unittest
from unittest.mock import MagicMock, PropertyMock
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
    class PortScannerError(Exception):
        pass
    class PortScannerHostDict(dict): # Simple mock for the type
        def hostname(self): return self.get('hostname', "")
        def state(self): return self.get('state', {}).get('state', "")
        def all_protocols(self): return list(self.get('protocols', {}).keys())
        # Add .get() to mimic dict behavior for protocol access like host_scan_data.get(proto, {})
        def get(self, key, default=None):
            if key in self: # Check if key exists directly (e.g. 'tcp', 'udp', 'osmatch')
                return self[key]
            # Fallback for other attributes that might be accessed via .get()
            # For example, if the internal structure of PortScannerHostDict uses .get for its own methods
            return super().get(key, default)


from nmap_scanner import NmapArgumentError, NmapScanParseError # Import custom exceptions

class TestNmapScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = NmapScanner()
        # Mock the nmap.PortScanner instance (self.nm)
        self.scanner.nm = MagicMock()

    def test_parse_results_no_hosts_found(self):
        # Mock nmap.PortScanner().all_hosts() to return an empty list
        self.scanner.nm.all_hosts.return_value = []
        
        hosts_data, error_message = self.scanner._parse_scan_results(do_os_fingerprint=False)
        
        self.assertEqual(hosts_data, [])
        self.assertEqual(error_message, "No hosts found.")

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
        result_data, error_msg = self.scanner.scan(target_host, False, 123)
        
        self.assertIsNone(result_data)
        self.assertIsNotNone(error_msg)
        self.assertIn("Argument error: Additional arguments must be a string.", error_msg)


    def test_scan_nmap_execution_error(self):
        self.scanner.nm.scan.side_effect = PortScannerError("Test Nmap Execution Error")
        
        target_host = "localhost"
        result_data, error_msg = self.scanner.scan(target_host, False, "-sV")
        
        self.assertIsNone(result_data)
        self.assertIsNotNone(error_msg)
        self.assertIn("Nmap execution error: Test Nmap Execution Error", error_msg)

    def test_build_scan_args_os_fingerprint(self):
        args = self.scanner._build_scan_args(do_os_fingerprint=True, additional_args_str="-T4")
        self.assertIn("-O", args.split())
        self.assertIn("-sV", args.split())
        self.assertIn("-T4", args.split())

    def test_build_scan_args_no_os_fingerprint(self):
        args = self.scanner._build_scan_args(do_os_fingerprint=False, additional_args_str="--top-ports 10")
        self.assertNotIn("-O", args.split())
        self.assertIn("-sV", args.split())
        self.assertIn("--top-ports", [a.split('=')[0] for a in args.split()])
        self.assertIn("10", args.split())


    def test_build_scan_args_additional_args_sV_handling(self):
        args_user_sV = self.scanner._build_scan_args(False, "-sV -p 80,443")
        self.assertEqual(args_user_sV.count("-sV"), 1)
        self.assertIn("-p", args_user_sV.split())

        args_user_A = self.scanner._build_scan_args(False, "-A")
        self.assertIn("-A", args_user_A.split())
        # -sV should not be added separately if -A is present as -A implies -sV
        self.assertNotIn("-sV", args_user_A.split()[1:])


    # --- Tests for _build_scan_args (New) ---

    def test_build_scan_args_with_nse_script(self):
        args = self.scanner._build_scan_args(False, "", nse_script="vuln")
        self.assertIn("--script=vuln", args)

    def test_build_scan_args_default_host_timeout(self):
        args = self.scanner._build_scan_args(False, "")
        self.assertIn("--host-timeout=60s", args)

    def test_build_scan_args_user_host_timeout_preserved(self):
        args_custom_s = self.scanner._build_scan_args(False, "--host-timeout=120s")
        self.assertIn("--host-timeout=120s", args_custom_s)
        self.assertEqual(args_custom_s.count("--host-timeout"), 1)

        args_custom_ms = self.scanner._build_scan_args(False, "--host-timeout 30ms")
        # shlex.split will handle "--host-timeout 30ms" as two items if not for shlex.join
        # but _build_scan_args joins them back. Result string should contain it.
        self.assertIn("--host-timeout 30ms", args_custom_ms) 
        # Ensure only one instance of --host-timeout is present
        found_timeout_arg = [arg for arg in args_custom_ms.split() if arg.startswith('--host-timeout') or arg == '30ms']
        # This reconstruction is a bit tricky because of shlex.split and join behavior.
        # A simpler check is if the exact string "--host-timeout 30ms" (if that was the input) or
        # "--host-timeout=30ms" is present. The current code joins with " ".
        # So, if input is "--host-timeout 30ms", it becomes part of the list as two elements
        # and then joined.
        self.assertTrue(any(arg.startswith("--host-timeout") for arg in args_custom_ms.split()))
        self.assertIn("30ms", args_custom_ms.split())


    def test_build_scan_args_shlex_split_failure(self):
        with self.assertRaisesRegex(NmapArgumentError, "Error parsing additional arguments:"):
            self.scanner._build_scan_args(False, "-sV 'mismatched_quote")

    # --- Tests for _parse_scan_results (New) ---

    def test_parse_results_with_udp_port_data(self):
        mock_host_ip = '192.168.1.3'
        mock_host_scan_data_dict = {
            'hostname': 'udphost.local',
            'state': {'state': 'up'},
            'protocols': {
                'udp': {
                    53: {'state': 'open|filtered', 'name': 'domain'},
                    161: {'state': 'open', 'name': 'snmp', 'product': 'SNMPv1 server'}
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
        mock_host_scan_data_dict = {
            'hostname': 'noports.local',
            'state': {'state': 'up'},
            'protocols': {'tcp': {}} # TCP protocol listed, but no ports
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
        self.scanner.nm.__getitem__.return_value = PortScannerHostDict(mock_data_empty_osmatch)
        hosts_data, _ = self.scanner._parse_scan_results(do_os_fingerprint=True)
        self.assertIsNone(hosts_data[0]['os_fingerprint'])
        self.assertIn("OS Fingerprint: No OS matches found.", hosts_data[0]['raw_details_text'])

        # Case 2: 'osmatch' key not present
        mock_data_no_osmatch_key = {'hostname': 'noos2','state':{'state':'up'}, 'protocols':{}}
        self.scanner.nm.__getitem__.return_value = PortScannerHostDict(mock_data_no_osmatch_key)
        hosts_data, _ = self.scanner._parse_scan_results(do_os_fingerprint=True)
        self.assertIsNone(hosts_data[0]['os_fingerprint'])
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
        detailed_mock_host_obj.hostname.side_effect = faulty_hostname
        # Need to provide other methods that are called before the error, if any.
        # .state() is called after .hostname() in current implementation for raw_details_parts.
        # However, the error should occur on .hostname() first.
        # .all_protocols() is called before .hostname() for the host_info dict.
        detailed_mock_host_obj.all_protocols.return_value = [] # Assume no protocols for simplicity

        self.scanner.nm.__getitem__.return_value = detailed_mock_host_obj
        
        with self.assertRaisesRegex(NmapScanParseError, "Error parsing data for host 192.168.1.6: Missing key"):
            self.scanner._parse_scan_results(do_os_fingerprint=False)

    # --- Tests for scan (integration - New) ---

    def test_scan_successful_with_nse_script(self):
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
