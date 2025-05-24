import unittest
from unittest.mock import MagicMock, PropertyMock
import sys
import os

# Adjust the path to import NmapScanner from the src directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from nmap_scanner import NmapScanner
# We need PortScannerError for one of the tests
try:
    from nmap import PortScannerError
except ImportError:
    # Define a dummy class if python-nmap is not installed,
    # tests relying on its actual presence might be skipped or adapted.
    class PortScannerError(Exception):
        pass

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
        mock_scan_data = {
            'hostnames': [{'name': 'testhost.local', 'type': 'PTR'}],
            'state': {'state': 'up', 'reason': 'arp-response'},
            'tcp': {
                80: {'state': 'open', 'reason': 'syn-ack', 'name': 'http', 'product': 'Apache httpd', 'version': '2.4.29'},
                443: {'state': 'closed', 'reason': 'reset', 'name': 'https', 'product': '', 'version': ''}
            },
            'udp': {} # No UDP ports for simplicity in this test
        }

        # Configure the mock nmap object
        self.scanner.nm.all_hosts.return_value = [mock_host_ip]
        # To allow scanner.nm[mock_host_ip]
        self.scanner.nm.__getitem__.return_value = MagicMock(**{
            'hostname.return_value': 'testhost.local',
            'state.return_value': 'up',
            'all_protocols.return_value': ['tcp'],
            '__getitem__.side_effect': lambda proto: mock_scan_data[proto] if proto == 'tcp' else {}
        })
        
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
        self.assertEqual(http_port['service']['product'], 'Apache httpd')
        self.assertEqual(http_port['service']['version'], '2.4.29')
        
        https_port = next(p for p in host_result['ports'] if p['portid'] == 443)
        self.assertEqual(https_port['state'], 'closed')

        self.assertIn(f"Host: {mock_host_ip} (testhost.local)", host_result['raw_details_text'])
        self.assertIn("Port: 80/tcp  State: open  Service: Name: http, Product: Apache httpd, Version: 2.4.29", host_result['raw_details_text'])
        self.assertNotIn("OS Fingerprint:", host_result['raw_details_text'])


    def test_parse_results_single_host_with_os_fingerprint(self):
        mock_host_ip = '192.168.1.2'
        mock_os_match_data = {
            'name': 'Linux 4.15', 
            'accuracy': '100',
            'osclass': [{
                'type': 'OS', 
                'vendor': 'Linux', 
                'osfamily': 'Linux', 
                'osgen': '4.X', 
                'accuracy': '100'
            }]
        }
        mock_scan_data = {
            'hostnames': [{'name': 'linuxhost.local', 'type': 'PTR'}],
            'state': {'state': 'up', 'reason': 'arp-response'},
            'tcp': {
                22: {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh', 'product': 'OpenSSH', 'version': '7.6p1 Ubuntu 4ubuntu0.3'}
            },
            'osmatch': [mock_os_match_data] # OS match data
        }

        self.scanner.nm.all_hosts.return_value = [mock_host_ip]

        # Create the mock for the host object returned by self.nm[mock_host_ip]
        mock_host_obj = MagicMock(name=f"HostMock_{mock_host_ip}")
        
        # Mock methods called on the host object
        mock_host_obj.hostname.return_value = 'linuxhost.local'
        mock_host_obj.state.return_value = 'up'
        mock_host_obj.all_protocols.return_value = ['tcp'] # Parser uses this to iterate protocols

        # Mock dictionary-like access for the host object (e.g., host_obj['tcp'], host_obj['osmatch'])
        # The mock_scan_data dictionary holds the data that these accesses should return.
        # For host_obj[proto]:
        #   The parser does host_scan_data[proto], so it expects proto (e.g. 'tcp') to be a key.
        # For host_obj['osmatch']:
        #   The parser checks "osmatch" in host_scan_data and then host_scan_data["osmatch"].
        
        def getitem_side_effect(key):
            # This side effect is for mock_host_obj['some_key']
            if key in mock_scan_data:
                return mock_scan_data[key]
            # If the key is not in mock_scan_data, raise KeyError,
            # which is typical dictionary behavior.
            # The parser code expects keys like 'tcp' to exist if they are in all_protocols().
            # For 'osmatch', it explicitly checks with "in" operator first.
            raise KeyError(f"Mock for host_obj does not have key: {key}")

        mock_host_obj.__getitem__.side_effect = getitem_side_effect
        
        # Configure __contains__ to reflect keys in mock_scan_data
        # This ensures "osmatch" in host_scan_data works as expected.
        mock_host_obj.__contains__.side_effect = lambda key: key in mock_scan_data
        
        self.scanner.nm.__getitem__.return_value = mock_host_obj
        
        hosts_data, error_message = self.scanner._parse_scan_results(do_os_fingerprint=True)
        
        self.assertIsNone(error_message)
        self.assertEqual(len(hosts_data), 1)
        host_result = hosts_data[0]
        
        self.assertIsNotNone(host_result['os_fingerprint'])
        self.assertEqual(host_result['os_fingerprint']['name'], 'Linux 4.15')
        self.assertEqual(host_result['os_fingerprint']['accuracy'], '100')
        self.assertEqual(len(host_result['os_fingerprint']['osclass']), 1)
        self.assertEqual(host_result['os_fingerprint']['osclass'][0]['vendor'], 'Linux')

        self.assertIn("OS Fingerprint:", host_result['raw_details_text'])
        self.assertIn("Name: Linux 4.15 (Accuracy: 100%)", host_result['raw_details_text'])

    def test_scan_invalid_arguments_type(self):
        # Test _build_scan_args indirectly via scan() when additional_args_str is not a string
        target_host = "localhost"
        result_data, error_msg = self.scanner.scan(target_host, False, 123) # 123 is not a string
        
        self.assertIsNone(result_data)
        self.assertEqual(error_msg, "Additional arguments must be a string.")

    def test_scan_nmap_execution_error(self):
        # Mock self.scanner.nm.scan() to raise PortScannerError
        self.scanner.nm.scan.side_effect = PortScannerError("Test Nmap Execution Error")
        
        target_host = "localhost"
        result_data, error_msg = self.scanner.scan(target_host, False, "-sV")
        
        self.assertIsNone(result_data)
        self.assertEqual(error_msg, "Nmap error: Test Nmap Execution Error")

    def test_build_scan_args_os_fingerprint(self):
        args = self.scanner._build_scan_args(do_os_fingerprint=True, additional_args_str="-T4")
        self.assertIn("-O", args)
        self.assertIn("-sV", args) # Should be added by default
        self.assertIn("-T4", args)

    def test_build_scan_args_no_os_fingerprint(self):
        args = self.scanner._build_scan_args(do_os_fingerprint=False, additional_args_str="--top-ports 10")
        self.assertNotIn("-O", args)
        self.assertIn("-sV", args)
        self.assertIn("--top-ports 10", args)

    def test_build_scan_args_additional_args_sV_handling(self):
        # If user provides -sV
        args_user_sV = self.scanner._build_scan_args(False, "-sV -p 80,443")
        self.assertEqual(args_user_sV.count("-sV"), 1) # Ensure -sV is not duplicated
        self.assertIn("-p 80,443", args_user_sV)

        # If user provides -A (which includes -sV)
        args_user_A = self.scanner._build_scan_args(False, "-A")
        self.assertIn("-A", args_user_A)
        self.assertNotIn("-sV", args_user_A.split()[1:]) # -sV should not be added separately if -A is present

    def test_parse_results_multiple_hosts(self):
        mock_host1_ip = '192.168.1.10'
        mock_scan1_data = {
            'hostnames': [{'name': 'host1.local', 'type': 'PTR'}], 'state': {'state': 'up'},
            'tcp': {22: {'state': 'open', 'name': 'ssh'}}
        }
        mock_host2_ip = '192.168.1.11'
        mock_scan2_data = {
            'hostnames': [{'name': 'host2.local', 'type': 'PTR'}], 'state': {'state': 'down'},
            'tcp': {} # No open ports
        }

        self.scanner.nm.all_hosts.return_value = [mock_host1_ip, mock_host2_ip]
        
        def getitem_side_effect(host_ip):
            if host_ip == mock_host1_ip:
                return MagicMock(**{
                    'hostname.return_value': 'host1.local', 'state.return_value': 'up',
                    'all_protocols.return_value': ['tcp'],
                    '__getitem__.side_effect': lambda proto: mock_scan1_data[proto]
                })
            elif host_ip == mock_host2_ip:
                return MagicMock(**{
                    'hostname.return_value': 'host2.local', 'state.return_value': 'down',
                    'all_protocols.return_value': ['tcp'],
                    '__getitem__.side_effect': lambda proto: mock_scan2_data[proto]
                })
            raise KeyError("Unknown host")

        self.scanner.nm.__getitem__.side_effect = getitem_side_effect
        
        hosts_data, error_message = self.scanner._parse_scan_results(do_os_fingerprint=False)

        self.assertIsNone(error_message)
        self.assertEqual(len(hosts_data), 2)
        
        host1_result = next(h for h in hosts_data if h['id'] == mock_host1_ip)
        self.assertEqual(host1_result['hostname'], 'host1.local')
        self.assertEqual(len(host1_result['ports']), 1)
        self.assertEqual(host1_result['ports'][0]['portid'], 22)

        host2_result = next(h for h in hosts_data if h['id'] == mock_host2_ip)
        self.assertEqual(host2_result['hostname'], 'host2.local')
        self.assertEqual(len(host2_result['ports']), 0)


if __name__ == '__main__':
    unittest.main()
