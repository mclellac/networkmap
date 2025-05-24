# nmap_scanner.py

try:
    import nmap
except ImportError as e:
    raise ImportError(
        "nmap module is not installed. Please install it using the command: pip install python-nmap"
    ) from e

import shlex
from typing import Tuple


class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(
        self, target: str, do_os_fingerprint: bool, additional_args_str: str
    ) -> Tuple[str, str]:
        scan_args = self._build_scan_args(do_os_fingerprint, additional_args_str)

        try:
            self.nm.scan(hosts=target, arguments=scan_args)
            return self._parse_scan_results()
        except nmap.PortScannerError as e:
            return "", f"Nmap error: {e}"
        except Exception as e:
            return "", f"A general error occurred: {e}"

    def _build_scan_args(
        self, do_os_fingerprint: bool, additional_args_str: str
    ) -> str:
        scan_args = "-O " if do_os_fingerprint else ""
        try:
            additional_args = shlex.split(additional_args_str)
            scan_args += " ".join(additional_args)
        except ValueError as e:  # Handle shlex errors
            raise ValueError(f"Invalid arguments: {e}")
        return scan_args

    def _parse_scan_results(self) -> Tuple[str, str]:
        if self.nm.all_hosts():
            output = ""
            for host in self.nm.all_hosts():
                output += f"Host: {host} ({self.nm[host].hostname()})\n"
                output += f"State: {self.nm[host].state()}\n"
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        output += f"Port: {port}/{proto} State: {self.nm[host][proto][port]['state']}\n"
                output += "\n"
            return output, ""
        else:
            return "", "No information found."
